/*
 * APEX Blindfold: page bootstrap.
 * A classic script, loaded on every page of the application. It finds the
 * element marked with data-bf-page and loads the ES module of that page from
 * the same static-files folder.
 */
(function () {
  'use strict';

  var base = new URL('.', document.currentScript.src);

  apex.jQuery(function () {
    var root = document.querySelector('[data-bf-page]');
    if (!root) {
      return; // for example the login page
    }
    import(new URL(root.dataset.bfPage + '.js', base))
      .then(function (pageModule) {
        return pageModule.mount(root);
      })
      .catch(function (error) {
        var box = document.createElement('p');
        box.className = 'bf-message bf-message--error';
        box.textContent = 'This page could not start: ' + error.message;
        root.prepend(box);
        throw error;
      });
  });
})();
