exports.header = null

exports.footer = {
  height: "1cm",
  contents: function(pageNum, numPages) {
    if(pageNum==1){
      return null;
    }
    exports.footer.height="1cm";
    return "<span style='float:left;font-size:10px;font-family:Cambria,Arial;'> [DATE] </span> <span style='float:right;font-size:10px;font-family:Cambria,Arial;'>" + pageNum + "</span>"
  }
}
