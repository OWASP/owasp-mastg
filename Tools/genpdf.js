var markdownpdf = require("markdown-pdf")
  , fs = require("fs")
  , split = require("split")
  , through = require("through")
  , duplexer = require("duplexer");
var lang = "";
var help = false;

if (process.argv.includes("-h")) {
  console.log("Helptext here");
  help = true;
} else if (process.argv.includes("-lang")) {
  lang = process.argv[process.argv.indexOf("-lang") + 1];
} else if (process.argv.includes("-l")) {
  lang = process.argv[process.argv.indexOf("-l") + 1];
}

if (!help) {
  if (lang == "" || lang == null) {
    lang = "../document/";
  } else {
    lang = "../document-" + lang +"/";
  }
  console.log("printing for " + lang);
  runPDF();
}

function preProcessMd () {
  // Split the input stream by lines
  var splitter = split()

  var replacer = through(function (data) {
    this.queue(data.replace("[date]", setDate()).replace("Images/", lang+"/Images/") + "\n")
  })

  splitter.pipe(replacer)
  return duplexer(splitter, replacer)
}

function setDate(){
  var today = new Date();
  var dd = today.getDate();
  var mm = today.getMonth()+1; //January is 0!
  var yyyy = today.getFullYear();

  if(dd<10) {
      dd = '0'+dd
  }

  if(mm<10) {
      mm = '0'+mm
  }

  return mm + '/' + dd + '/' + yyyy;
}

function runPDF() {
  var mdDocs = [
      lang+"0x00-Header.md",
      lang+"Foreword.md",
      lang+"0x02-Frontispiece.md",
      lang+"0x03-Overview.md",
      lang+"0x04-General-Testing-Guide.md",
      lang+"0x04a-Mobile-App-Taxonomy.md",
      lang+"0x04b-Mobile-App-Security-Testing.md",
      lang+"0x04c-Tampering-and-Reverse-Engineering.md",
      lang+"0x04e-Testing-Authentication-and-Session-Management.md",
      lang+"0x04f-Testing-Network-Communication.md",
      lang+"0x04g-Testing-Cryptography.md",
      lang+"0x04h-Testing-Code-Quality.md",
      lang+"0x05-Android-Testing-Guide.md",
      lang+"0x05a-Platform-Overview.md",
      lang+"0x05b-Basic-Security_Testing.md",
      lang+"0x05d-Testing-Data-Storage.md",
      lang+"0x05e-Testing-Cryptography.md",
      lang+"0x05f-Testing-Local-Authentication.md",
      lang+"0x05g-Testing-Network-Communication.md",
      lang+"0x05h-Testing-Platform-Interaction.md",
      lang+"0x05i-Testing-Code-Quality-and-Build-Settings.md",
      lang+"0x05c-Reverse-Engineering-and-Tampering.md",
      lang+"0x05j-Testing-Resiliency-Against-Reverse-Engineering.md",
      lang+"0x06-iOS-Testing-Guide.md",
      lang+"0x06a-Platform-Overview.md",
      lang+"0x06b-Basic-Security-Testing.md",
      lang+"0x06d-Testing-Data-Storage.md",
      lang+"0x06e-Testing-Cryptography.md",
      lang+"0x06f-Testing-Local-Authentication.md",
      lang+"0x06g-Testing-Network-Communication.md",
      lang+"0x06h-Testing-Platform-Interaction.md",
      lang+"0x06i-Testing-Code-Quality-and-Build-Settings.md",
      lang+"0x06c-Reverse-Engineering-and-Tampering.md",
      lang+"0x06j-Testing-Resiliency-Against-Reverse-Engineering.md",
      lang+"0x07-Appendix.md",
      lang+"0x08-Testing-Tools.md",
      lang+"0x09-Suggested-Reading.md"
    ],
    bookPath = "./test.pdf";
// todo:
// 1. fix new page after before h1 starts
// 2. fix/add TOC
// 3. add changelog
// 4. Fix date to version-tag
// 5. Fix page numering
// A. make sure doc + pdf + html is uploaded by travis
// B. make sure a markdown linter runs at PR!
// C. update gitbook automatically

  markdownpdf({preProcessMd: preProcessMd})
    .concat.from(mdDocs)
    .to(bookPath, function() {
      console.log("Created", bookPath);
    });
}
