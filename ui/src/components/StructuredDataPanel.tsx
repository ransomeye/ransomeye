import type { ReactNode } from "react";

function humanizeKey(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatScalar(v: unknown): ReactNode {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (typeof v === "number" && Number.isFinite(v)) return v.toLocaleString();
  if (typeof v === "string") return v.length > 0 ? v : "—";
  return String(v);
}

type Props = {
  data: Record<string, unknown> | null | undefined;
  title?: string;
  /** Keys to hide (e.g. internal lineage blobs handled elsewhere) */
  omitKeys?: Set<string>;
  nested?: boolean;
};

/**
 * Renders API objects as readable key/value tables — not raw JSON.
 */
export function StructuredDataPanel({ data, title, omitKeys, nested }: Props) {
  if (!data || Object.keys(data).length === 0) {
    return <p className="soc-muted" style={{ margin: 0 }}>No data.</p>;
  }

  const rows: { rawKey: string; key: string; value: ReactNode }[] = [];

  for (const [k, v] of Object.entries(data)) {
    if (omitKeys?.has(k)) continue;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      rows.push({
        rawKey: k,
        key: humanizeKey(k),
        value: (
          <div className="soc-nested-kv">
            <StructuredDataPanel data={v as Record<string, unknown>} nested omitKeys={omitKeys} />
          </div>
        ),
      });
      continue;
    }
    if (Array.isArray(v)) {
      rows.push({
        rawKey: k,
        key: humanizeKey(k),
        value:
          v.length === 0 ? (
            "—"
          ) : (
            <ul className="soc-kv-list">
              {v.slice(0, 24).map((item, i) => (
                <li key={i}>
                  {item !== null && typeof item === "object" && !Array.isArray(item) ? (
                    <StructuredDataPanel data={item as Record<string, unknown>} nested omitKeys={omitKeys} />
                  ) : (
                    formatScalar(item)
                  )}
                </li>
              ))}
              {v.length > 24 && <li className="soc-muted">… {v.length - 24} more</li>}
            </ul>
          ),
      });
      continue;
    }
    rows.push({ rawKey: k, key: humanizeKey(k), value: formatScalar(v) });
  }

  return (
    <div className={nested ? "soc-structured-nested" : "soc-structured"}>
      {title && !nested && <h3 className="soc-structured__title">{title}</h3>}
      <table className={`soc-table ${nested ? "soc-table--nested" : ""}`}>
        <tbody>
          {rows.map((r) => (
            <tr key={r.rawKey}>
              <th className="soc-th soc-th--kv" scope="row">
                {r.key}
              </th>
              <td className="soc-td soc-td--kv">{r.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
