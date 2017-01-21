#!/usr/bin/env ruby
# Generate HTML TOC for the OWASP MSTG

require "redcarpet"
require "htmlentities"

class CustomRender < Redcarpet::Render::HTML_TOC

  def header(title, level)

    title = HTMLEntities.new.encode(title) # Securitay!
    anchor = title.downcase.gsub!(' ','-')

    case level
    when 1
      "<a href=\"Document/#{$curfile}\##{anchor}\"><h1>#{title}</h1></a>\n"
    when 2
      "<a href=\"Document/#{$curfile}\##{anchor}\"><h2>#{title}</h2></a>\n"
    when 3
      "<p><a href=\"Document/#{$curfile}\##{anchor}\">#{title}</a>\</p>\n"
    end
  end
end

markdown = Redcarpet::Markdown.new(CustomRender, fenced_code_blocks: true)

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

Dir.foreach('../Document') do |fn|
  if fn =~ /\.md$/
    $curfile = fn
    file = File.open("../Document/#{fn}")
                contents = file.read
                puts markdown.render(contents)
  end
end

Dir.foreach('../Document/Testcases') do |fn|
  if fn =~ /\.md$/
    file = File.open("../Document/Testcases/#{fn}")
                contents = file.read
                puts markdown.render(contents)
  end
end

puts "</body>\n"