function loadImages() {
  var imgDefer = document.getElementsByTagName('img');
  for (var i = 0; i < imgDefer.length; i++) {
    imgDefer[i].onerror = function() { this.src = "/static/images/default-person.jpg"; };
    if (imgDefer[i].getAttribute('data-src')) {
      imgDefer[i].setAttribute('src', imgDefer[i].getAttribute('data-src'));
    }
  }
}

window.onload = loadImages;