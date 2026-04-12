package sine

import (
	"math"
	"sort"
)

type Signal struct {
	Source string
	Weight float64
	Time   int64
}

type Score struct {
	Value      float64
	Confidence float64
}

// Evaluate reduces signals into a deterministic score.
// Pure function: no randomness, no IO, no global state.
func Evaluate(signals []Signal) Score {
	if len(signals) == 0 {
		return Score{}
	}

	// Copy for purity; sorting in-place would mutate caller data.
	ss := make([]Signal, len(signals))
	copy(ss, signals)
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].Source != ss[j].Source {
			return ss[i].Source < ss[j].Source
		}
		if ss[i].Time != ss[j].Time {
			return ss[i].Time < ss[j].Time
		}
		return ss[i].Weight < ss[j].Weight
	})

	// Time anchor is max Time (deterministic).
	maxT := ss[len(ss)-1].Time
	minT := ss[0].Time
	for i := range ss {
		if ss[i].Time > maxT {
			maxT = ss[i].Time
		}
		if ss[i].Time < minT {
			minT = ss[i].Time
		}
	}

	// Temporal decay: w' = w * exp(-lambda * delta_t)
	// Interpret Signal.Time as epoch millis (int64).
	const halfLifeMs = 30_000.0
	lambda := math.Ln2 / halfLifeMs

	// Signal normalization + correlation:
	// - group by Source (contiguous after sort)
	// - clamp weights, apply decay
	// - normalize each source contribution by its L1 magnitude to prevent any single source dominating
	// - compute intra-source consistency (variance + sign coherence)
	var (
		globalSum, globalC float64 // Kahan
		corrSum, corrC     float64 // Kahan
		srcCount           int
		globalVarSum       float64
		globalVarC         float64
	)

	i := 0
	for i < len(ss) {
		j := i + 1
		for j < len(ss) && ss[j].Source == ss[i].Source {
			j++
		}
		srcCount++

		// First pass: compute decayed weights + L1 magnitude + mean (Kahan).
		var (
			l1       float64
			l1c      float64
			mean     float64
			meanc    float64
			count    int
			absSum   float64
			srcSum   float64
			srcSumC  float64
		)
		for k := i; k < j; k++ {
			w := clampWeight(ss[k].Weight)
			if math.IsNaN(w) || math.IsInf(w, 0) {
				continue
			}
			dt := float64(maxT - ss[k].Time)
			if dt < 0 {
				dt = 0
			}
			decay := math.Exp(-lambda * dt)
			x := w * decay

			// L1 magnitude.
			ax := math.Abs(x)
			yy := ax - l1c
			tt := l1 + yy
			l1c = (tt - l1) - yy
			l1 = tt

			absSum += ax

			// Mean (Kahan).
			count++
			d := x - meanc
			m := mean + d
			meanc = (m - mean) - d
			mean = m

			// Sum (Kahan) for coherence.
			sy := x - srcSumC
			st := srcSum + sy
			srcSumC = (st - srcSum) - sy
			srcSum = st
		}
		if count == 0 {
			i = j
			continue
		}
		mean /= float64(count)
		if l1 <= 0 {
			i = j
			continue
		}

		// Second pass: variance (stable) and normalized contribution.
		var (
			varSum, varC float64
			normSum, normC float64
		)
		for k := i; k < j; k++ {
			w := clampWeight(ss[k].Weight)
			if math.IsNaN(w) || math.IsInf(w, 0) {
				continue
			}
			dt := float64(maxT - ss[k].Time)
			if dt < 0 {
				dt = 0
			}
			x := w * math.Exp(-lambda*dt)

			dv := x - mean
			vx := dv * dv
			vy := vx - varC
			vt := varSum + vy
			varC = (vt - varSum) - vy
			varSum = vt

			nx := x / l1
			ny := nx - normC
			nt := normSum + ny
			normC = (nt - normSum) - ny
			normSum = nt
		}
		variance := varSum / float64(count)

		// Intra-source consistency: penalize high variance and cancellation.
		signCoherence := 0.0
		if absSum > 0 {
			signCoherence = math.Abs(srcSum) / absSum
		}
		consistency := signCoherence / (1.0 + variance)

		// Aggregate normalized contribution and correlation.
		addKahan(&globalSum, &globalC, normSum)
		addKahan(&corrSum, &corrC, consistency)
		addKahan(&globalVarSum, &globalVarC, variance)

		i = j
	}

	if srcCount == 0 {
		return Score{}
	}

	correlationFactor := corrSum / float64(srcCount)
	if correlationFactor < 0 {
		correlationFactor = 0
	} else if correlationFactor > 1 {
		correlationFactor = 1
	}

	weighted := globalSum * correlationFactor
	value := 0.5 * (math.Tanh(weighted) + 1.0)
	value = clamp01(value)

	// Confidence = f(num_sources, variance, recency)
	srcFactor := math.Log1p(float64(srcCount)) / math.Log1p(8)
	if srcFactor > 1 {
		srcFactor = 1
	}
	globalVar := globalVarSum / float64(srcCount)
	varFactor := 1.0 / (1.0 + globalVar)

	span := float64(maxT - minT)
	if span < 0 {
		span = 0
	}
	recencyFactor := math.Exp(-lambda * span)

	conf := srcFactor * varFactor * recencyFactor
	conf = clamp01(conf)

	return Score{Value: value, Confidence: conf}
}

func clampWeight(w float64) float64 {
	const maxW = 1000.0
	if w > maxW {
		return maxW
	}
	if w < -maxW {
		return -maxW
	}
	return w
}

func addKahan(sum *float64, c *float64, x float64) {
	y := x - *c
	t := *sum + y
	*c = (t - *sum) - y
	*sum = t
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

