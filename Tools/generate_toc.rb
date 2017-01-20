#!/usr/bin/env ruby
# Generate HTML TOC for the OWASP MSTG

require "redcarpet"

class CustomRender < Redcarpet::Render::HTML_TOC

  def header(title, level)
    case level
    when 1
      "<h1 id=\"firstheading\" class=\"firstheading\"><span dir=\"auto\">#{title}</h1>\n</span>"
    when 2
      "<h2>#{title}</h2>"
    when 3
      "<p>#{title}</p>\n"
    end
  end
end

markdown = Redcarpet::Markdown.new(CustomRender, fenced_code_blocks: true)

Dir.foreach('../Document') do |fn|
  if fn =~ /\.md$/
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
