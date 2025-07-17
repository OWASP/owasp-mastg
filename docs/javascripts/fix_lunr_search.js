(() => {
  const OriginalRegExp = RegExp;

  const HookedRegExp = function (pattern, flags) {
    const regex = new OriginalRegExp(pattern, flags);
    console.log("🧪 New RegExp created:", {
      pattern,
      flags,
      source: regex.source,
    });
    return regex;
  };

  HookedRegExp.prototype = OriginalRegExp.prototype;
  HookedRegExp.prototype.constructor = HookedRegExp;

  // Copy static methods like RegExp.escape (if polyfilled)
  Object.getOwnPropertyNames(OriginalRegExp).forEach((key) => {
    if (!(key in HookedRegExp)) {
      HookedRegExp[key] = OriginalRegExp[key];
    }
  });

  window.RegExp = HookedRegExp;
})();
