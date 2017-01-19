#!/usr/bin/env ruby
# Generate HTML TOC for the OWASP MSTG

require "redcarpet"

markdown = Redcarpet::Markdown.new(Redcarpet::Render::HTML_TOC, fenced_code_blocks: true)

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

