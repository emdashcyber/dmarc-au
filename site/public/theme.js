(function () {
  var root = document.documentElement;
  var storageKey = 'emdash-theme';
  var darkPreference = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  var savedTheme = null;
  var button = null;

  try {
    var saved = window.localStorage.getItem(storageKey);
    if (saved === 'light' || saved === 'dark') savedTheme = saved;
  } catch (error) {
    // Keep using the device preference when storage is unavailable.
  }

  var currentTheme = function () {
    return savedTheme || (darkPreference && darkPreference.matches ? 'dark' : 'light');
  };

  var syncButton = function () {
    if (button) button.setAttribute('aria-pressed', String(currentTheme() === 'dark'));
  };

  var applyTheme = function () {
    var theme = currentTheme();
    root.setAttribute('data-theme', theme);

    var themeColors = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < themeColors.length; i++) {
      themeColors[i].setAttribute('media', 'all');
      themeColors[i].setAttribute('content', theme === 'dark' ? '#0d1117' : '#fcfcfb');
    }

    syncButton();
  };

  var attachButton = function () {
    button = document.getElementById('theme-toggle');
    if (!button) return;

    syncButton();
    button.addEventListener('click', function () {
      savedTheme = currentTheme() === 'dark' ? 'light' : 'dark';
      try {
        window.localStorage.setItem(storageKey, savedTheme);
      } catch (error) {
        // The selected theme still applies for this page view.
      }
      applyTheme();
    });
  };

  applyTheme();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachButton);
  } else {
    attachButton();
  }

  if (darkPreference) {
    var followDeviceTheme = function () {
      if (!savedTheme) applyTheme();
    };
    if (darkPreference.addEventListener) {
      darkPreference.addEventListener('change', followDeviceTheme);
    } else if (darkPreference.addListener) {
      darkPreference.addListener(followDeviceTheme);
    }
  }
})();
