// Navigation bar

var pathname = location.pathname;
var basename = pathname.substring(1 + pathname.lastIndexOf("/"));

var links = new Array();

links[0] = new Object();
links[0].url = "readme.html";
links[0].text = "readme";

links[1] = new Object();
links[1].url = "install.html";
links[1].text = "install";

links[2] = new Object();
links[2].url = "user-guide.html";
links[2].text = "user&nbsp;guide";

links[3] = new Object();
links[3].url = "dev-guide.html";
links[3].text = "developer&nbsp;guide";

document.write('<div class="navbar">');

for (var i = 0; i < links.length; i++) {

  if (basename == links[i].url) {
    document.write('<b>');
    document.write(links[i].text);
    document.write('</b>');
  } else {
    document.write('<a href="');
    document.write(links[i].url);
    document.write('">');
    document.write(links[i].text);
    document.write('</a>');
  }
  if (i + 1 < links.length) {
    document.write('&nbsp;&nbsp;|&nbsp;&nbsp;');
  }
}

document.writeln('</div>');
document.writeln();
