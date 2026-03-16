import { defineConfig } from "tsup"

export default defineConfig({
  entry: {
    "retich-auth": "src/retich-auth.ts",
    react: "src/react.tsx",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  external: ["react"],
  sourcemap: true,
})
