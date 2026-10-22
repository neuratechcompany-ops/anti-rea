const mode = process.argv[2];
if (mode === "json") process.stdout.write(JSON.stringify({ ok: true, artifact: process.argv[3] }));
else if (mode === "env") process.stdout.write(JSON.stringify({ leaked: Object.hasOwn(process.env, "ANTI_REA_SENTINEL_SECRET") }));
else if (mode === "empty") process.exit(0);
else if (mode === "bad-json") process.stdout.write("not json");
else if (mode === "large") process.stdout.write("x".repeat(2048));
else process.exit(7);
