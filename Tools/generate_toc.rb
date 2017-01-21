#!/usr/bin/env ruby
# Generate HTML TOC for the OWASP MSTG

require "redcarpet"
require "htmlentities"

class DocumentRender < Redcarpet::Render::HTML_TOC

  def header(title, level)

    title = HTMLEntities.new.encode(title) # Securitay!
    anchor = title.downcase.gsub!(' ','-')

    case level
    when 1
      "<a href=\"https://github.com/OWASP/owasp-mstg/blob/master/Document/#{$curfile}\##{anchor}\"><h1>#{title}</h1></a>\n"
    when 2
      "<a href=\"https://github.com/OWASP/owasp-mstg/blob/master/Document/#{$curfile}\##{anchor}\"><h2>#{title}</h2></a>\n"
    when 3
      "<p><a href=\"https://github.com/OWASP/owasp-mstg/blob/master/Document/#{$curfile}\##{anchor}\">#{title}</a>\</p>\n"
    end
  end
end

class TestcaseRender < Redcarpet::Render::HTML_TOC

  def header(title, level)

    title = HTMLEntities.new.encode(title) # Securitay!
    anchor = title.downcase.gsub!(' ','-')

    case level
    when 1
      "<a href=\"https://github.com/OWASP/owasp-mstg/blob/master/Document/Testcases/#{$curfile}\##{anchor}\"><h1>#{title}</h1></a>\n"
    when 2
      "<a href=\"https://github.com/OWASP/owasp-mstg/blob/master/Document/Testcases/#{$curfile}\##{anchor}\"><h2>#{title}</h2></a>\n"
    when 3
      "<p><a href=\"https://github.com/OWASP/owasp-mstg/blob/master/Document/Testcases/#{$curfile}\##{anchor}\">#{title}</a>\</p>\n"
    end
  end
end




puts '''
<html>
<head>
<style>

body { font-family: Arial, \'Helvetica Neue\', Helvetica, sans-serif; }

p { font-size: 1.1em; }

</style>
</head>
<body>
'''

markdown = Redcarpet::Markdown.new(DocumentRender, fenced_code_blocks: true)

Dir.foreach('../Document') do |fn|
  if fn =~ /\.md$/
    $curfile = fn
    file = File.open("../Document/#{fn}")
                contents = file.read
                puts markdown.render(contents)
  end
end

markdown = Redcarpet::Markdown.new(TestcaseRender, fenced_code_blocks: true)

Dir.foreach('../Document/Testcases') do |fn|
  if fn =~ /\.md$/
    file = File.open("../Document/Testcases/#{fn}")
                contents = file.read
                puts markdown.render(contents)
  end
end

puts "</body>\n"