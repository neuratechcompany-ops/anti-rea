#!/usr/bin/env node
import { createHash, randomBytes } from "node:crypto";
import { open, readFile, unlink } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { parse } from "acorn";
import { chacha20Poly1305Seal } from "./chacha20-poly1305.mjs";

const MARKER = "@anti-rea-vm";
const OPS = ["CONST", "VOID", "LOAD", "STORE", "GET", "OBJECT", "ARRAY", "BINARY", "UNARY", "DUP", "POP", "JUMP", "JUMP_FALSE", "RETURN", "INTRINSIC"];
const BINARY = ["+", "-", "*", "/", "%", "**", "<", "<=", ">", ">=", "==", "!=", "===", "!==", "&", "|", "^", "<<", ">>", ">>>"];
const UNARY = ["!", "+", "-", "~", "typeof"];
const INTRINSICS = new Set(["abs", "ceil", "floor", "max", "min", "round", "sign", "trunc"]);

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: virtualize-javascript.mjs --input BUNDLE.js --output VM.js --report REPORT.json --seed INTEGER [--canaries FILE.json] [--key-mode embedded|external] [--key-slot IDENTIFIER --key-env ENV_NAME]\n");
  process.exit(64);
}

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) usage("invalid arguments");
    const name = key.slice(2);
    if (result[name] !== undefined) usage(`duplicate argument: ${key}`);
    result[name] = value;
  }
  for (const name of ["input", "output", "report", "seed"]) if (result[name] === undefined) usage(`--${name} is required`);
  if (!/^(0|[1-9][0-9]{0,9})$/.test(result.seed) || Number(result.seed) > 0xffffffff) usage("--seed must be an integer from 0 to 4294967295");
  result["key-mode"] ??= "embedded";
  if (!new Set(["embedded", "external"]).has(result["key-mode"])) usage("--key-mode must be embedded or external");
  if (result["key-mode"] === "external") {
    if (!/^[A-Za-z_$][A-Za-z0-9_$]{3,63}$/.test(result["key-slot"] ?? "")) usage("external key mode requires --key-slot with a 4..64 character JavaScript identifier");
    if (!/^[A-Z][A-Z0-9_]{2,63}$/.test(result["key-env"] ?? "")) usage("external key mode requires --key-env naming a build environment variable");
    if (!/^[a-f0-9]{64}$/.test(process.env[result["key-env"]] ?? "")) usage("external key environment value must be 32-byte lowercase hex");
  } else if (result["key-slot"] !== undefined || result["key-env"] !== undefined) usage("--key-slot and --key-env are only valid with external key mode");
  return result;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function prng(seed) {
  let state = seed >>> 0 || 0x9e3779b9;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function shuffle(values, next) {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const other = next() % (index + 1);
    [result[index], result[other]] = [result[other], result[index]];
  }
  return result;
}

function compileFunction(node, functionSeed) {
  if (node.async || node.generator || node.expression) throw new Error(`${node.id?.name ?? "marked function"}: async, generators, and expression bodies are unsupported`);
  if (!node.id || node.params.some((item) => item.type !== "Identifier")) throw new Error("marked functions require a name and simple identifier parameters");
  const locals = new Map();
  for (const parameter of node.params) {
    if (locals.has(parameter.name)) throw new Error(`${node.id.name}: duplicate parameter ${parameter.name}`);
    locals.set(parameter.name, locals.size);
  }
  const constants = [];
  const constantKeys = new Map();
  const instructions = [];
  const next = prng(functionSeed);
  const opcodes = Object.fromEntries(shuffle(OPS, next).map((name, index) => [name, 17 + index * 7 + (next() % 5)]));
  const binaryIds = Object.fromEntries(shuffle(BINARY, next).map((name, index) => [name, index + 3]));
  const unaryIds = Object.fromEntries(shuffle(UNARY, next).map((name, index) => [name, index + 2]));

  function fail(nodeValue, message) {
    throw new Error(`${node.id.name}: ${message} at source offset ${nodeValue.start}`);
  }

  function constant(value) {
    const key = `${typeof value}:${JSON.stringify(value)}`;
    if (!constantKeys.has(key)) {
      constantKeys.set(key, constants.length);
      constants.push(value);
    }
    return constantKeys.get(key);
  }

  function emit(name, argument = 0) {
    instructions.push([opcodes[name], argument]);
    return instructions.length - 1;
  }

  function compileExpression(value) {
    switch (value.type) {
      case "Literal":
        if (value.regex || typeof value.value === "bigint") fail(value, "regex and bigint literals are unsupported");
        emit("CONST", constant(value.value));
        return;
      case "Identifier":
        if (value.name === "undefined") emit("VOID");
        else if (locals.has(value.name)) emit("LOAD", locals.get(value.name));
        else fail(value, `free identifier ${value.name} is forbidden`);
        return;
      case "MemberExpression":
        if (value.optional || value.property.type === "PrivateIdentifier") fail(value, "optional/private member access is unsupported");
        compileExpression(value.object);
        if (value.computed) compileExpression(value.property);
        else emit("CONST", constant(value.property.name));
        emit("GET");
        return;
      case "BinaryExpression":
        if (!(value.operator in binaryIds)) fail(value, `binary operator ${value.operator} is unsupported`);
        compileExpression(value.left);
        compileExpression(value.right);
        emit("BINARY", binaryIds[value.operator]);
        return;
      case "LogicalExpression": { // preserve short-circuit values
        if (value.operator !== "&&" && value.operator !== "||" && value.operator !== "??") fail(value, `logical operator ${value.operator} is unsupported`);
        compileExpression(value.left);
        emit("DUP");
        if (value.operator === "??") fail(value, "nullish coalescing is not yet supported");
        const branch = emit("JUMP_FALSE", 0);
        if (value.operator === "||") {
          const done = emit("JUMP", 0);
          instructions[branch][1] = instructions.length;
          emit("POP");
          compileExpression(value.right);
          instructions[done][1] = instructions.length;
        } else {
          emit("POP");
          compileExpression(value.right);
          instructions[branch][1] = instructions.length;
        }
        return;
      }
      case "UnaryExpression":
        if (!(value.operator in unaryIds)) fail(value, `unary operator ${value.operator} is unsupported`);
        compileExpression(value.argument);
        emit("UNARY", unaryIds[value.operator]);
        return;
      case "ConditionalExpression": { 
        compileExpression(value.test);
        const otherwise = emit("JUMP_FALSE", 0);
        compileExpression(value.consequent);
        const done = emit("JUMP", 0);
        instructions[otherwise][1] = instructions.length;
        compileExpression(value.alternate);
        instructions[done][1] = instructions.length;
        return;
      }
      case "ObjectExpression":
        for (const property of value.properties) {
          if (property.type !== "Property" || property.kind !== "init" || property.method || property.computed || property.key.type === "PrivateIdentifier") fail(property, "only ordinary object properties are supported");
          const key = property.key.type === "Identifier" ? property.key.name : property.key.value;
          if (typeof key !== "string" && typeof key !== "number") fail(property, "object property key must be a string or number");
          emit("CONST", constant(String(key)));
          compileExpression(property.value);
        }
        emit("OBJECT", value.properties.length);
        return;
      case "ArrayExpression":
        if (value.elements.some((item) => item === null || item.type === "SpreadElement")) fail(value, "array holes and spread are unsupported");
        for (const element of value.elements) compileExpression(element);
        emit("ARRAY", value.elements.length);
        return;
      case "AssignmentExpression": {
        if (value.left.type !== "Identifier" || !locals.has(value.left.name)) fail(value, "only assignments to local identifiers are supported");
        if (value.operator === "=") compileExpression(value.right);
        else {
          const binary = value.operator.slice(0, -1);
          if (!(binary in binaryIds)) fail(value, `assignment operator ${value.operator} is unsupported`);
          emit("LOAD", locals.get(value.left.name));
          compileExpression(value.right);
          emit("BINARY", binaryIds[binary]);
        }
        emit("DUP");
        emit("STORE", locals.get(value.left.name));
        return;
      }
      case "CallExpression": {
        const callee = value.callee;
        if (value.optional || callee.type !== "MemberExpression" || callee.computed || callee.object.type !== "Identifier" || callee.object.name !== "Math" || callee.property.type !== "Identifier" || !INTRINSICS.has(callee.property.name)) fail(value, "only selected Math intrinsics are supported");
        if (value.arguments.some((item) => item.type === "SpreadElement")) fail(value, "spread call arguments are unsupported");
        for (const argument of value.arguments) compileExpression(argument);
        emit("INTRINSIC", constant([callee.property.name, value.arguments.length]));
        return;
      }
      default:
        fail(value, `expression ${value.type} is unsupported`);
    }
  }

  function declare(name, value) {
    if (locals.has(name)) throw new Error(`${node.id.name}: duplicate or shadowed local ${name}`);
    const slot = locals.size;
    locals.set(name, slot);
    compileExpression(value);
    emit("STORE", slot);
  }

  function compileStatement(value) {
    switch (value.type) {
      case "VariableDeclaration":
        if (value.kind === "var") fail(value, "var declarations are unsupported; use let or const");
        for (const declaration of value.declarations) {
          if (declaration.id.type !== "Identifier" || declaration.init === null) fail(declaration, "locals require identifier bindings and initializers");
          declare(declaration.id.name, declaration.init);
        }
        return;
      case "ReturnStatement":
        if (value.argument === null) emit("VOID");
        else compileExpression(value.argument);
        emit("RETURN");
        return;
      case "ExpressionStatement":
        compileExpression(value.expression);
        emit("POP");
        return;
      case "IfStatement": { 
        compileExpression(value.test);
        const otherwise = emit("JUMP_FALSE", 0);
        compileStatement(value.consequent);
        if (value.alternate) {
          const done = emit("JUMP", 0);
          instructions[otherwise][1] = instructions.length;
          compileStatement(value.alternate);
          instructions[done][1] = instructions.length;
        } else instructions[otherwise][1] = instructions.length;
        return;
      }
      case "BlockStatement":
        for (const statement of value.body) compileStatement(statement);
        return;
      default:
        fail(value, `statement ${value.type} is unsupported`);
    }
  }

  compileStatement(node.body);
  if (instructions.length === 0 || instructions.at(-1)[0] !== opcodes.RETURN) {
    emit("VOID");
    emit("RETURN");
  }
  return { name: node.id.name, params: node.params.map((item) => item.name), locals: locals.size, constants, instructions, opcodes, binaryIds, unaryIds };
}

function encryptPayload(payload, seed) {
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  const next = prng(seed);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] ^= next() & 0xff;
  return bytes.toString("base64");
}

function encryptExternalPayload(payload, key, nonce, aad) {
  const sealed = chacha20Poly1305Seal(Buffer.from(JSON.stringify(payload), "utf8"), key, nonce, aad);
  return Buffer.concat([sealed.ciphertext, sealed.tag]).toString("base64");
}

function externalDecryptSource(keySlot, nonce, aad) {
  const nonceBase64 = nonce.toString("base64");
  const aadBase64 = aad.toString("base64");
  return `var G=globalThis[${JSON.stringify(keySlot)}];if(typeof G!=="function")throw Error("protected program unavailable");var h=G(d.slice(7));if(!(h instanceof Uint8Array)||h.length!==32)throw Error("protected program unavailable");var k=new Uint8Array(h);h.fill(0);h=null;var J=function(e){return typeof Buffer==="function"?Buffer.from(e,"base64"):Uint8Array.from(atob(e),function(t){return t.charCodeAt(0)})},u=J(${JSON.stringify(nonceBase64)}),E=J(${JSON.stringify(aadBase64)}),T=q.slice(q.length-16),C=q.slice(0,q.length-16),R=function(e,t){return(e<<t|e>>>(32-t))>>>0},Q=function(e,t,r,n,o){e[t]=(e[t]+e[r])>>>0;e[o]=R(e[o]^e[t],16);e[n]=(e[n]+e[o])>>>0;e[r]=R(e[r]^e[n],12);e[t]=(e[t]+e[r])>>>0;e[o]=R(e[o]^e[t],8);e[n]=(e[n]+e[o])>>>0;e[r]=R(e[r]^e[n],7)},V=new DataView(k.buffer,k.byteOffset,k.byteLength),U=new DataView(u.buffer,u.byteOffset,u.byteLength),H=function(g){var A=[1634760805,857760878,2036477234,1797285236];for(var y=0;y<8;y++)A.push(V.getUint32(y*4,true));A.push(g>>>0,U.getUint32(0,true),U.getUint32(4,true),U.getUint32(8,true));var B=A.slice();for(y=0;y<10;y++){Q(B,0,4,8,12);Q(B,1,5,9,13);Q(B,2,6,10,14);Q(B,3,7,11,15);Q(B,0,5,10,15);Q(B,1,6,11,12);Q(B,2,7,8,13);Q(B,3,4,9,14)}var W=new Uint8Array(64),D=new DataView(W.buffer);for(y=0;y<16;y++)D.setUint32(y*4,(B[y]+A[y])>>>0,true);return W},P=function(e){var t=0,r;for(r=0;r<e.length;r++)t+=e[r].length;var n=new Uint8Array(t),o=0;for(r=0;r<e.length;r++){n.set(e[r],o);o+=e[r].length}return n},Z=function(e){var t=new Uint8Array(8),r=BigInt(e);for(var n=0;n<8;n++){t[n]=Number(r&BigInt(255));r>>=BigInt(8)}return t},F=function(e){var t=BigInt(0);for(var r=e.length-1;r>=0;r--)t=(t<<BigInt(8))|BigInt(e[r]);return t},O=H(0).slice(0,32),r=F(O.slice(0,16))&BigInt("0x0ffffffc0ffffffc0ffffffc0fffffff"),s=F(O.slice(16,32)),pe=E.length%16?new Uint8Array(16-E.length%16):new Uint8Array(0),pc=C.length%16?new Uint8Array(16-C.length%16):new Uint8Array(0),M=P([E,pe,C,pc,Z(E.length),Z(C.length)]),a=BigInt(0),pr=(BigInt(1)<<BigInt(130))-BigInt(5);for(var m=0;m<M.length;m+=16){var L=M.slice(m,Math.min(m+16,M.length));a=((a+F(L)+(BigInt(1)<<BigInt(L.length*8)))*r)%pr}var X=(a+s)&((BigInt(1)<<BigInt(128))-BigInt(1)),df=0;for(var y=0;y<16;y++)df|=Number((X>>BigInt(y*8))&BigInt(255))^T[y];if(df!==0){O.fill(0);k.fill(0);throw Error("protected program authentication failed")}q=C;for(var z=0,g=1;z<q.length;z+=64,g++){var W=H(g);for(y=0;y<64&&z+y<q.length;y++)q[z+y]^=W[y]}O.fill(0);k.fill(0);`;
}

function runtimeSource(compiled, functionId, seed, encrypted, ordinal, keyMode, keySlot, nonce, aad) {
  const cache = `__arv_${sha256(`${compiled.name}\0${seed}\0${ordinal}`).slice(0, 12)}`;
  const o = compiled.opcodes;
  const binaryCases = Object.entries(compiled.binaryIds).map(([operator, id]) => {
    const expression = operator === "**" ? "a ** b" : `a ${operator} b`;
    return `case ${id}:s.push(${expression});break;`;
  }).join("");
  const unaryCases = Object.entries(compiled.unaryIds).map(([operator, id]) => `case ${id}:s.push(${operator === "typeof" ? "typeof a" : `${operator}a`});break;`).join("");
  return `var ${cache};\nfunction ${compiled.name}(${compiled.params.join(",")}){\n` +
    `var p=${cache};if(!p){var d=${JSON.stringify(`ARVMID:${functionId}`)},q=typeof Buffer==="function"?Buffer.from(${JSON.stringify(encrypted)},"base64"):Uint8Array.from(atob(${JSON.stringify(encrypted)}),function(c){return c.charCodeAt(0)});${keyMode === "external" ? externalDecryptSource(keySlot, nonce, aad) : `var x=${seed >>> 0}||2654435769;for(var z=0;z<q.length;z++){x^=x<<13;x^=x>>>17;x^=x<<5;q[z]^=x&255}`}var pt=new TextDecoder().decode(q);q.fill(0);p=${cache}=JSON.parse(pt);pt="";if(p.d!==d.slice(7))throw Error("protected program identity mismatch")}\n` +
    `var v=Array(${compiled.locals}),s=[],i=0,n,a,b,k,r,j;for(j=0;j<arguments.length;j++)v[j]=arguments[j];for(;;){n=p.i[i++];switch(n[0]){` +
    `case ${o.CONST}:s.push(p.c[n[1]]);break;case ${o.VOID}:s.push(void 0);break;case ${o.LOAD}:s.push(v[n[1]]);break;case ${o.STORE}:v[n[1]]=s.pop();break;` +
    `case ${o.GET}:k=s.pop();a=s.pop();s.push(a[k]);break;case ${o.OBJECT}:r={};a=Array(n[1]);for(j=n[1]-1;j>=0;j--){b=s.pop();k=s.pop();a[j]=[k,b]}for(j=0;j<a.length;j++)r[a[j][0]]=a[j][1];s.push(r);break;` +
    `case ${o.ARRAY}:r=s.splice(s.length-n[1],n[1]);s.push(r);break;case ${o.BINARY}:b=s.pop();a=s.pop();switch(n[1]){${binaryCases}}break;` +
    `case ${o.UNARY}:a=s.pop();switch(n[1]){${unaryCases}}break;case ${o.DUP}:s.push(s[s.length-1]);break;case ${o.POP}:s.pop();break;` +
    `case ${o.JUMP}:i=n[1];break;case ${o.JUMP_FALSE}:if(!s.pop())i=n[1];break;case ${o.RETURN}:return s.pop();` +
    `case ${o.INTRINSIC}:r=p.c[n[1]];a=s.splice(s.length-r[1],r[1]);s.push(Math[r[0]].apply(Math,a));break;default:throw Error("invalid protected program")}}}`;
}

async function writeExclusive(destination, content) {
  const handle = await open(destination, "wx", 0o644);
  try { await handle.writeFile(content); } finally { await handle.close(); }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const inputPath = path.resolve(args.input);
  const outputPath = path.resolve(args.output);
  const reportPath = path.resolve(args.report);
  if (new Set([inputPath, outputPath, reportPath]).size !== 3) throw new Error("input, output, and report paths must differ");
  const input = await readFile(inputPath);
  if (input.length === 0 || input.length > 25 * 1024 * 1024) throw new Error("input must contain 1..26214400 bytes");
  const source = input.toString("utf8");
  if (Buffer.byteLength(source) !== input.length) throw new Error("input must be valid UTF-8 JavaScript");
  const comments = [];
  const ast = parse(source, { ecmaVersion: "latest", sourceType: "module", allowHashBang: true, ranges: true, onComment: comments });
  const candidates = ast.body.filter((item) => item.type === "FunctionDeclaration").map((node) => {
    const comment = comments.filter((item) => item.end <= node.start && item.value.includes(MARKER) && source.slice(item.end, node.start).trim() === "").at(-1);
    return comment ? { node, comment } : null;
  }).filter(Boolean);
  if (candidates.length === 0) throw new Error(`no top-level function declaration is marked with ${MARKER}`);
  const seed = Number(args.seed);
  const keyMode = args["key-mode"];
  const keySlot = args["key-slot"] ?? null;
  const externalKey = keyMode === "external" ? Buffer.from(process.env[args["key-env"]], "hex") : null;
  const replacements = [];
  const functions = [];
  const inputSha256 = sha256(input);
  for (let ordinal = 0; ordinal < candidates.length; ordinal += 1) {
    const { node, comment } = candidates[ordinal];
    const functionSeed = Number.parseInt(sha256(`${seed}\0${ordinal}\0${source.slice(node.start, node.end)}`).slice(0, 8), 16) >>> 0;
    const compiled = compileFunction(node, functionSeed);
    const sourceSha256 = sha256(source.slice(node.start, node.end));
    const functionId = sha256(`anti-rea-function-v1\0${inputSha256}\0${sourceSha256}\0${ordinal}\0${compiled.name}`);
    const payload = { d: functionId, c: compiled.constants, i: compiled.instructions };
    const nonce = keyMode === "external" ? randomBytes(12) : null;
    const aad = keyMode === "external" ? Buffer.from(JSON.stringify({ v: 3, functionId, inputSha256, name: compiled.name, sourceSha256, ordinal })) : null;
    const encrypted = keyMode === "external" ? encryptExternalPayload(payload, externalKey, nonce, aad) : encryptPayload(payload, functionSeed);
    replacements.push({ start: comment.start, end: node.end, text: runtimeSource(compiled, functionId, functionSeed, encrypted, ordinal, keyMode, keySlot, nonce, aad) });
    functions.push({ id: functionId, name: compiled.name, parameters: compiled.params.length, locals: compiled.locals, instructions: compiled.instructions.length, encryptedPayloadBytes: Buffer.byteLength(encrypted), sourceSha256, aadSha256: aad === null ? null : sha256(aad) });
  }
  let transformed = source;
  for (const replacement of replacements.sort((a, b) => b.start - a.start)) transformed = transformed.slice(0, replacement.start) + replacement.text + transformed.slice(replacement.end);
  const output = Buffer.from(transformed, "utf8");
  const canaries = args.canaries === undefined ? [] : JSON.parse(await readFile(args.canaries, "utf8"));
  if (!Array.isArray(canaries) || canaries.some((item) => typeof item !== "string" || item.length < 4 || item.length > 1024)) throw new Error("canaries must be an array of strings, each 4..1024 characters");
  const leakedCanaries = canaries.filter((item) => output.includes(Buffer.from(item)));
  if (leakedCanaries.length > 0) throw new Error(`virtualized artifact retains ${leakedCanaries.length} plaintext canary value(s)`);
  const report = {
    schemaVersion: 1,
    transformer: { name: "anti-rea-selective-vm", version: "1.2.0", parser: "acorn@8.15.0" },
    key: { mode: keyMode, slot: keySlot, provider: keyMode === "external" ? "function-v1" : null, encryption: keyMode === "external" ? "chacha20-poly1305" : "embedded-xorshift", aad: keyMode === "external" ? "input-function-context-v3" : null },
    input: { path: inputPath, bytes: input.length, sha256: sha256(input) },
    output: { path: outputPath, bytes: output.length, sha256: sha256(output), sizeRatio: Math.round((output.length / input.length) * 1000) / 1000 },
    functions,
    canaries: { supplied: canaries.length, plaintextRecovered: leakedCanaries.length, sha256: canaries.map((item) => sha256(Buffer.from(item))) },
    limitations: [
      "only explicitly marked top-level pure functions in the documented JavaScript subset are accepted",
      "the local VM raises reverse-engineering cost but its interpreter, decoded program, inputs, and outputs remain observable at runtime",
      "run the ordinary JavaScript transform after virtualization and validate behavior with target-specific probes",
    ],
  };
  const created = [];
  try {
    await writeExclusive(outputPath, output); created.push(outputPath);
    await writeExclusive(reportPath, `${JSON.stringify(report, null, 2)}\n`); created.push(reportPath);
  } catch (error) {
    for (const file of created.reverse()) await unlink(file).catch(() => {});
    throw error;
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`javascript virtualization error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
