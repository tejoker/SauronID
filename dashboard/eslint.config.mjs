// ESLint 9 flat config. eslint-config-next@16 ships flat-config arrays via its
// sub-exports, so we spread them directly (no @eslint/eslintrc FlatCompat shim).
import coreWebVitals from "eslint-config-next/core-web-vitals";
import typescript from "eslint-config-next/typescript";
import jsxA11y from "eslint-plugin-jsx-a11y";

const config = [
  { ignores: [".next/**", "node_modules/**", "public/**", "next-env.d.ts"] },
  ...coreWebVitals,
  ...typescript,
  {
    // Keep React 19 purity rules release-blocking. A genuine force-dynamic
    // Server Component clock snapshot is suppressed at its call site with a
    // narrow explanation; client effects must remain cascade-free.
    rules: {
      // Accessibility is release-blocking, not advisory.
      //
      // Enterprise and public-sector procurement asks for a VPAT or an
      // EN 301 549 statement, and "we believe it is accessible" is not an
      // answer to one. At `warn` these gate nothing and violations accumulate;
      // the console is small enough today (23 pages, 11 components) that
      // `error` is affordable, and it stops being affordable later.
      //
      // The rules are enabled by name rather than by spreading
      // `jsxA11y.flatConfigs.recommended`: eslint-config-next already registers
      // the jsx-a11y plugin (at `warn`, and only a subset), and a second
      // registration is a hard ConfigError. This re-uses the plugin next
      // loaded and promotes its full recommended set.
      // Promote what `recommended` enables, and leave what it disables alone.
      // Mapping every key to "error" also switches on the rules the preset
      // deliberately turns off — `label-has-for` is deprecated and superseded
      // by `label-has-associated-control`, and enabling it produced 21 errors
      // that were duplicates of a rule already reporting the same elements.
      ...Object.fromEntries(
        Object.entries(jsxA11y.flatConfigs.recommended.rules).map(([rule, level]) => {
          const severity = Array.isArray(level) ? level[0] : level;
          const disabled = severity === "off" || severity === 0;
          return [rule, disabled ? "off" : "error"];
        })
      ),
      // The ARIA Authoring Practices listbox pattern is built from ul/li, so
      // those two mappings are correct rather than exceptions. Spelled out here
      // instead of suppressed at the call site, so the next listbox gets the
      // same treatment and any OTHER non-interactive element taking an
      // interactive role still fails.
      "jsx-a11y/no-noninteractive-element-to-interactive-role": [
        "error",
        {
          ul: ["listbox", "menu", "menubar", "radiogroup", "tablist", "tree", "treegrid"],
          li: ["menuitem", "option", "row", "tab", "treeitem"],
          table: ["grid"],
          td: ["gridcell"],
        },
      ],
      "react-hooks/set-state-in-effect": "error",
      "react-hooks/purity": "error",
      // A leading underscore already means "declared for its type, never read"
      // — the codebase uses it for mock signatures that must match an interface
      // (see __tests__/tenant.test.ts). Without this the convention produces
      // warnings, and warnings nobody can act on are how real ones get ignored.
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
];

export default config;
