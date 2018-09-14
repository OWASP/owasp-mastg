exports.header = null


exports.footer = {
  height: "1cm",
  contents: function(pageNum, numPages) {
    return "<span style='float:left;font-size:10px;'>[DATE]</span> <span style='float:right;font-size:10px;'>" + pageNum + " / " + numPages + "</span>"
  }
}
