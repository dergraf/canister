// GoatCounter analytics loader for the mdBook docs.
//
// mdBook's `additional-js` adds a plain <script src=…> tag; it can't
// express custom attributes like `data-goatcounter`. This tiny loader
// injects the real GoatCounter snippet dynamically, which is equivalent
// to writing the tag in markup but keeps the book.toml config simple.
(function () {
  var s = document.createElement('script');
  s.async = true;
  s.dataset.goatcounter = 'https://dergraf.goatcounter.com/count';
  s.src = '//gc.zgo.at/count.js';
  document.head.appendChild(s);
})();
