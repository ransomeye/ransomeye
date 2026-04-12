#!/usr/bin/env node
/**
 * Compiler-backed TS/TSX module graph via TypeScript createProgram (same as tsc).
 * Emits JSON to stdout: { file_outgoing_repo, file_incoming_repo, errors }
 */
import { createRequire } from "module";
import { dirname, join, relative, resolve } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const uiRoot = join(repoRoot, "ui");
const require = createRequire(import.meta.url);
const ts = require(join(uiRoot, "node_modules/typescript"));

function collectImports(sourceFile) {
  const out = [];
  function visit(node) {
    if (
      ts.isImportDeclaration(node) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      out.push(node.moduleSpecifier.text);
    }
    if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      out.push(node.moduleSpecifier.text);
    }
    if (ts.isImportEqualsDeclaration(node) && node.moduleReference && ts.isExternalModuleReference(node.moduleReference)) {
      const e = node.moduleReference.expression;
      if (e && ts.isStringLiteral(e)) {
        out.push(e.text);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return out;
}

function main() {
  const prevCwd = process.cwd();
  process.chdir(uiRoot);
  const configPath = join(uiRoot, "tsconfig.app.json");
  const read = ts.readConfigFile(configPath, ts.sys.readFile);
  if (read.error) {
    console.log(
      JSON.stringify({
        errors: [ts.flattenDiagnosticMessageText(read.error.messageText, "\n")],
        file_outgoing_repo: {},
        file_incoming_repo: {},
      })
    );
    return;
  }
  const parsed = ts.parseJsonConfigFileContent(
    read.config,
    ts.sys,
    dirname(configPath)
  );
  if (parsed.errors.length) {
    process.chdir(prevCwd);
    const msgs = parsed.errors.map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
    console.log(JSON.stringify({ errors: msgs, file_outgoing_repo: {}, file_incoming_repo: {} }));
    return;
  }

  const program = ts.createProgram({
    rootNames: parsed.fileNames,
    options: parsed.options,
    projectReferences: parsed.projectReferences,
  });
  const diags = ts.getPreEmitDiagnostics(program).filter(
    (d) => d.category === ts.DiagnosticCategory.Error
  );
  if (diags.length) {
    process.chdir(prevCwd);
    const fmt = diags.map((d) =>
      ts.flattenDiagnosticMessageText(d.messageText, "\n")
    ).join("\n");
    console.log(
      JSON.stringify({
        errors: [`typescript:${fmt}`],
        file_outgoing_repo: {},
        file_incoming_repo: {},
      })
    );
    return;
  }

  const outgoing = new Map();
  const incoming = new Map();

  function inProjectSource(rel) {
    return (
      rel.startsWith("ui/src/") &&
      !rel.includes("node_modules")
    );
  }

  function addEdge(fromRel, toRel) {
    if (!inProjectSource(fromRel) || !inProjectSource(toRel)) {
      return;
    }
    if (fromRel === toRel) {
      return;
    }
    if (!outgoing.has(fromRel)) {
      outgoing.set(fromRel, new Set());
    }
    outgoing.get(fromRel).add(toRel);
    if (!incoming.has(toRel)) {
      incoming.set(toRel, new Set());
    }
    incoming.get(toRel).add(fromRel);
  }

  for (const sf of program.getSourceFiles()) {
    if (sf.isDeclarationFile) {
      continue;
    }
    const abs = sf.fileName;
    let fromRel = relative(repoRoot, abs).replace(/\\/g, "/");
    if (fromRel.startsWith("..")) {
      continue;
    }
    const opts = program.getCompilerOptions();
    for (const spec of collectImports(sf)) {
      const res = ts.resolveModuleName(spec, abs, opts, ts.sys);
      const rm = res.resolvedModule;
      if (!rm || !rm.resolvedFileName) {
        continue;
      }
      let toAbs = rm.resolvedFileName;
      let toRel = relative(repoRoot, toAbs).replace(/\\/g, "/");
      if (toRel.startsWith("..")) {
        continue;
      }
      addEdge(fromRel, toRel);
    }
  }

  const toObj = (m) => {
    const o = {};
    const keys = [...m.keys()].sort((a, b) => a.localeCompare(b));
    for (const k of keys) {
      o[k] = [...m.get(k)].sort((a, b) => a.localeCompare(b));
    }
    return o;
  };

  process.chdir(prevCwd);
  console.log(
    JSON.stringify({
      errors: [],
      file_outgoing_repo: toObj(outgoing),
      file_incoming_repo: toObj(incoming),
    })
  );
}

main();
