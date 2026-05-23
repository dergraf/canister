// Canister recipe-inference engine.
//
// Reads the recipes.json emitted by `can-docgen` and derives the graph the
// guided builder reasons over — role, tags, suggested companions — from
// existing fields (category, name, description, explicit `suggests`).
// The recipe schema deliberately exposes only a single explicit hint
// (`suggests`); everything else is inferred here so adding a recipe
// rarely means editing the builder.
//
// Exposes a single global: `window.Inference`.

(function () {
  'use strict';

  // ---- Role mapping (parent directory → role) -------------------------

  const CATEGORY_TO_ROLE = {
    languages: 'language',
    'package-managers': 'package-manager',
    editors: 'editor',
    vcs: 'vcs',
    services: 'service',
    container: 'container',
    system: 'system',
    core: 'core',
  };

  // Curated set of "system-level toolchain installers" — package-manager
  // recipes the user is likely answering "where did your toolchain come
  // from?" with. Distinguished from language package managers (npm, pip,
  // cargo, hex …) which the wizard reaches via per-language suggestions.
  const TOOLCHAIN_INSTALLER_NAMES = new Set([
    'homebrew', 'nix', 'nix-home-manager', 'asdf', 'mise',
    'flatpak', 'snap', 'gnu-store',
  ]);

  // Recipes that name a forge / hosted-git provider. Forges always pair
  // with `git` (the local VCS) and usually with a forge-specific CLI.
  const FORGE_SERVICE_NAMES = new Set(['github']);

  // Recipes that describe a remote SaaS / API endpoint rather than a
  // language-package registry. Used to split the "services" role into
  // two wizard sections: registries (paired with package managers) and
  // remote APIs (standalone consumers).
  const REMOTE_API_NAMES = new Set([
    // AI / inference
    'anthropic', 'openai', 'huggingface', 'opencode-ai',
    // SaaS / infra
    'aws', 'slack', 'stripe',
  ]);

  // Stop-words removed from description tokens before they become tags.
  const STOPWORDS = new Set([
    'a', 'an', 'the', 'and', 'or', 'with', 'via', 'for', 'on', 'in', 'of',
    'to', 'is', 'no', 'not', 'be', 'this', 'that', 'these', 'use', 'used',
    'using', 'plus', 'when', 'so', 'compose', 'compose-with', 'composes',
    'recipe', 'recipes', 'env', 'token', 'tokens', 'config', 'configuration',
    'denied', 'allowed', 'access', 'mounts', 'mount', 'cache', 'caches',
  ]);

  // Inferred-suggest patterns scanned across the description. Each pattern
  // captures one suggested recipe name. The names must resolve in the
  // bundled recipe set; unresolved hits are dropped.
  const DESC_SUGGEST_PATTERNS = [
    /compose(?:s|d)?\s+with\s+`([\w-]+)`/gi,
    /pair(?:s|ed)?\s+with\s+`([\w-]+)`/gi,
    /requires?\s+`([\w-]+)`/gi,
  ];

  // ---- Tokenisation & helpers -----------------------------------------

  function tokenize(text) {
    if (!text) return [];
    return String(text)
      .toLowerCase()
      .replace(/[`"'(){}[\],.;:!?/\\]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length >= 2 && !STOPWORDS.has(t));
  }

  function uniqueByOrder(arr) {
    const seen = new Set();
    const out = [];
    for (const v of arr) {
      if (!seen.has(v)) { seen.add(v); out.push(v); }
    }
    return out;
  }

  // ---- Enrichment ------------------------------------------------------

  function enrich(rawRecipes) {
    const known = new Set(rawRecipes.map(r => r.name));

    const enriched = rawRecipes.map(r => {
      const role = CATEGORY_TO_ROLE[r.category] || r.category || 'core';
      const explicitSuggests = Array.isArray(r.suggests) ? r.suggests.slice() : [];

      const inferredSuggests = [];
      for (const re of DESC_SUGGEST_PATTERNS) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(r.description || '')) !== null) {
          const candidate = m[1];
          if (candidate && known.has(candidate) && candidate !== r.name) {
            inferredSuggests.push(candidate);
          }
        }
      }
      const allSuggests = uniqueByOrder([...explicitSuggests, ...inferredSuggests])
        .filter(name => name !== r.name);

      const tags = uniqueByOrder([
        r.category,
        role,
        ...tokenize(r.name),
        ...tokenize(r.description),
      ].filter(Boolean));

      const isInstaller = TOOLCHAIN_INSTALLER_NAMES.has(r.name);
      const isForge = FORGE_SERVICE_NAMES.has(r.name);
      const isRemoteApi = REMOTE_API_NAMES.has(r.name);

      return Object.assign({}, r, {
        role,
        tags,
        explicitSuggests,
        inferredSuggests,
        suggests: allSuggests,
        isInstaller,
        isForge,
        isRemoteApi,
      });
    });

    const byName = new Map(enriched.map(r => [r.name, r]));
    const byRole = new Map();
    const byTag = new Map();
    for (const r of enriched) {
      if (!byRole.has(r.role)) byRole.set(r.role, []);
      byRole.get(r.role).push(r);
      for (const t of r.tags) {
        if (!byTag.has(t)) byTag.set(t, []);
        byTag.get(t).push(r);
      }
    }

    // ---- Reverse-suggestion index (B is suggested by A → reverse[B] += A)
    const reverse = new Map();
    for (const r of enriched) {
      for (const target of r.suggests) {
        if (!reverse.has(target)) reverse.set(target, []);
        reverse.get(target).push(r.name);
      }
    }

    function get(name) { return byName.get(name); }

    function suggestionsFor(name) {
      const r = byName.get(name);
      return r ? r.suggests.slice() : [];
    }

    /**
     * Explain why `suggested` was offered after the user picked `picked`.
     * Returns a short sentence suitable for a tooltip.
     */
    function explain(picked, suggested) {
      const p = byName.get(picked);
      const s = byName.get(suggested);
      if (!p || !s) return '';
      if (p.explicitSuggests.includes(suggested)) {
        return `Suggested because the \`${picked}\` recipe lists \`${suggested}\` as a natural companion.`;
      }
      if (p.inferredSuggests.includes(suggested)) {
        return `Inferred from \`${picked}\`'s description ("${p.description}").`;
      }
      return `Suggested alongside \`${picked}\`.`;
    }

    /**
     * Full-text search across name, description, role, and tags.
     * Returns matches scored by how many tokens hit.
     */
    function search(query) {
      const q = (query || '').trim().toLowerCase();
      if (!q) return enriched.slice();
      const tokens = q.split(/\s+/).filter(Boolean);
      const scored = enriched.map(r => {
        let score = 0;
        const hay = [r.name, r.description, r.role, ...(r.tags || [])]
          .filter(Boolean).join(' ').toLowerCase();
        for (const t of tokens) {
          if (r.name.toLowerCase().includes(t)) score += 3;
          if (hay.includes(t)) score += 1;
        }
        return [score, r];
      });
      return scored
        .filter(([s]) => s > 0)
        .sort((a, b) => b[0] - a[0])
        .map(([, r]) => r);
    }

    /**
     * Given a set of currently picked recipe names, compute the
     * "next-hop" suggestion set: recipes any pick suggests, minus the
     * ones already picked. Each entry carries the source pick(s) so we
     * can render a "why" tooltip.
     */
    function nextHops(pickedSet) {
      const out = new Map();
      for (const pickName of pickedSet) {
        const p = byName.get(pickName);
        if (!p) continue;
        for (const target of p.suggests) {
          if (pickedSet.has(target)) continue;
          if (!byName.has(target)) continue;
          if (!out.has(target)) out.set(target, new Set());
          out.get(target).add(pickName);
        }
      }
      return out; // Map<targetName, Set<sourcePickName>>
    }

    return {
      recipes: enriched,
      byName,
      byRole,
      byTag,
      reverse,
      get,
      suggestionsFor,
      explain,
      search,
      nextHops,
    };
  }

  // Public API
  window.Inference = {
    enrich,
    CATEGORY_TO_ROLE,
    TOOLCHAIN_INSTALLER_NAMES,
    FORGE_SERVICE_NAMES,
    REMOTE_API_NAMES,
  };
})();
