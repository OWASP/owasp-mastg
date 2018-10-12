exports.header = null

exports.footer = {
  height: "1cm",
  contents: function(pageNum, numPages) {
    return "<span style='float:left;font-size:10px;font-family:Cambria,Arial;'> [DATE] </span> <span style='float:right;font-size:10px;font-family:Cambria,Arial;'>" + pageNum + "</span>"
  }
}
