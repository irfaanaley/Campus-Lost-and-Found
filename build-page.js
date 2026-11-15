// Regenerates lib/page.js from public/index.html. Run "node build-page.js" after editing the HTML.
const fs = require('fs');
const html = fs.readFileSync(__dirname + '/public/index.html', 'utf8');
fs.writeFileSync(__dirname + '/lib/page.js', 'module.exports = ' + JSON.stringify(html) + ';\n');
console.log('lib/page.js written (' + html.length + ' chars)');
