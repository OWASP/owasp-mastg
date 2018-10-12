/**
 * This is a first attempt in making a PDF using markdownpdf .
 * Please note that it is done in my spare time as a quick prototype: tackling one issue after another
 * Feel free to rewrite it as the core of this project is the actual resulting PDF, not necessary this javascript.
 * Author: Jeroen Willemsen
 */
var markdownpdf = require("markdown-pdf"),
  fs = require("fs"),
  split = require("split"),
  through = require("through"),
  duplexer = require("duplexer");
var Remarkable = require("remarkable");
var replace = require("replace-in-file");
var toc = require("markdown-toc");
var fs = require("fs");

var lang = "";
var langdir = "";
var tag = "";
var help = false;
var releaseNotes = "";

if (process.argv.includes("-h")) {
  console.log("Helptext here");
  help = true;
}
if (process.argv.includes("-lang")) {
  lang = process.argv[process.argv.indexOf("-lang") + 1];
} else if (process.argv.includes("-l")) {
  lang = process.argv[process.argv.indexOf("-l") + 1];
}
if (process.argv.includes("-tag")) {
  tag = process.argv[process.argv.indexOf("-tag") + 1];
}
if (tag != "") {
  tag = tag + " ";
}
tag = tag + "Date: " + setDate();

if (process.argv.includes("-relnotes")) {
  releaseNotes = process.argv[process.argv.indexOf("-relnotes") + 1];
} else {
  releaseNotes = generateRelNotes();
}

if (!help) {
  if (lang == "" || lang == null) {
    lang = "EN";
    langdir = "../Document/";
  } else {
    langdir = "../Document-" + lang + "/";
  }
  console.log("printing for " + lang);
  runPDF();
}

function preProcessRunningJs() {
  var options = {
    files: "running.js",
    from: "[DATE]",
    to: "[" + tag + "]"
  };
  try {
    const changes = replace.sync(options);
    console.log("Modified files:", changes.join(", "));
  } catch (error) {
    console.error("Error occurred:", error);
  }
}

function postProcessRunningJS() {
  const options = {
    files: "running.js",
    from: "[" + tag + "]",
    to: "[DATE]"
  };
  try {
    const changes = replace.sync(options);
    console.log("Modified files:", changes.join(", "));
  } catch (error) {
    console.error("Error occurred:", error);
  }
}

function generateRelNotes(){

  return fs.readFileSync("../CHANGELOG.md", "utf8");
}

function preProcessMd() {
  // Split the input stream by lines
  var splitter = split();
  var tocRendered = getToc();
  var replacer = through(function(data) {
    this.queue(
      data
        .replace("[date]", tag)
        .replace("[RELEASE_NOTES]", releaseNotes)
        .replace("[TOCCCC]", tocRendered)
        .replace("Images/", langdir + "/Images/") + "\n"
    );
  });

  splitter.pipe(replacer);
  return duplexer(splitter, replacer);
}

function setDate() {
  var today = new Date();
  var dd = today.getDate();
  var mm = today.getMonth() + 1; //January is 0!
  var yyyy = today.getFullYear();

  if (dd < 10) {
    dd = "0" + dd;
  }

  if (mm < 10) {
    mm = "0" + mm;
  }

  return mm + "/" + dd + "/" + yyyy;
}

function getPreDocSet() {
  return [langdir + "0x00-Header.md", langdir + "Foreword.md"];
}
function getPostDocSet() {
  return [
    "changelog_and_toc.md",
    langdir + "0x02-Frontispiece.md",
    langdir + "0x03-Overview.md",
    langdir + "0x04-General-Testing-Guide.md",
    langdir + "0x04a-Mobile-App-Taxonomy.md",
    langdir + "0x04b-Mobile-App-Security-Testing.md",
    langdir + "0x04c-Tampering-and-Reverse-Engineering.md",
    langdir + "0x04e-Testing-Authentication-and-Session-Management.md",
    langdir + "0x04f-Testing-Network-Communication.md",
    langdir + "0x04g-Testing-Cryptography.md",
    langdir + "0x04h-Testing-Code-Quality.md",
    langdir + "0x05-Android-Testing-Guide.md",
    langdir + "0x05a-Platform-Overview.md",
    langdir + "0x05b-Basic-Security_Testing.md",
    langdir + "0x05d-Testing-Data-Storage.md",
    langdir + "0x05e-Testing-Cryptography.md",
    langdir + "0x05f-Testing-Local-Authentication.md",
    langdir + "0x05g-Testing-Network-Communication.md",
    langdir + "0x05h-Testing-Platform-Interaction.md",
    langdir + "0x05i-Testing-Code-Quality-and-Build-Settings.md",
    langdir + "0x05c-Reverse-Engineering-and-Tampering.md",
    langdir + "0x05j-Testing-Resiliency-Against-Reverse-Engineering.md",
    langdir + "0x06-iOS-Testing-Guide.md",
    langdir + "0x06a-Platform-Overview.md",
    langdir + "0x06b-Basic-Security-Testing.md",
    langdir + "0x06d-Testing-Data-Storage.md",
    langdir + "0x06e-Testing-Cryptography.md",
    langdir + "0x06f-Testing-Local-Authentication.md",
    langdir + "0x06g-Testing-Network-Communication.md",
    langdir + "0x06h-Testing-Platform-Interaction.md",
    langdir + "0x06i-Testing-Code-Quality-and-Build-Settings.md",
    langdir + "0x06c-Reverse-Engineering-and-Tampering.md",
    langdir + "0x06j-Testing-Resiliency-Against-Reverse-Engineering.md",
    langdir + "0x07-Appendix.md",
    langdir + "0x08-Testing-Tools.md",
    langdir + "0x09-Suggested-Reading.md"
  ];
}
function getDocSet() {
  return getPreDocSet().concat(getPostDocSet());
}

function getToc() {
  var resultString = "";
  var docSet = getPostDocSet();
  docSet.forEach(function(filename) {
    resultString = resultString + fs.readFileSync(filename, "utf8");
  });
  var renderedToc = toc(resultString, { maxdepth: 3 }).content;
  return renderedToc;
}

function runPDF() {
  var mdDocs = getDocSet(),
    bookPath = "./../generated/MSTG-" + lang + ".pdf";

  preProcessRunningJs();
  markdownpdf({
    preProcessMd: preProcessMd,
    remarkable: {
      html: true,
      breaks: true
    },
    runningsPath: "running.js",
    cssPath: "pdf.css"
  })
    .concat.from(mdDocs)
    .to(bookPath, function() {
      console.log("Created", bookPath);
      postProcessRunningJS();
    });
}
