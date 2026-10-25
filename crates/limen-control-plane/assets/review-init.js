// Review decisions: removing someone's access needs a reason. The browser asks
// for it on the comment box only when "Remove" is pressed, so "Keep" stays one
// click. Kept in its own file so the page needs no inline script (CSP).
(function () {
  document.querySelectorAll('form[data-decide]').forEach(function (form) {
    var comment = form.querySelector('input[name="comment"]');
    form.querySelectorAll('button[name="decision"]').forEach(function (b) {
      b.addEventListener('click', function () {
        comment.required = b.value === 'flag';
        comment.placeholder = comment.required ? 'Say why it should go' : 'Comment (optional)';
      });
    });
  });
})();
