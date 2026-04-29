import { defineConfig } from "eslint/config";
import globals from "globals";
import js from "@eslint/js";


export default defineConfig([
  {
    ignores: [
      "node_modules/**",
      "uploads/**",
      "logs/**",
      "backend/logs/**"
    ]
  },
  { files: ["**/*.{js,mjs,cjs}"], plugins: { js }, extends: ["js/recommended"] },
  {
    files: ["backend/**/*.js"],
    languageOptions: {
      sourceType: "commonjs",
      globals: globals.node
    }
  },
  {
    files: ["ecosystem.config.js"],
    languageOptions: {
      sourceType: "commonjs",
      globals: globals.node
    }
  },
  {
    files: ["backend/__tests__/**/*.js"],
    languageOptions: {
      sourceType: "commonjs",
      globals: { ...globals.node, ...globals.jest }
    }
  },
  {
    files: ["frontend/**/*.js"],
    languageOptions: {
      sourceType: "script",
      globals: globals.browser
    },
    rules: {
      "no-unused-vars": "off"
    }
  }
]);
