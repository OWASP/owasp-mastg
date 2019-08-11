# Style Guide

The following rules are meant to ensure consistency of the MSTG:

1. Keep the content factual, brief and focused. Avoid duplicating other sections of the guide;
2. Refrain from advertising commercial tools or services;
3. When giving technical instructions, address the reader in the second person.

## 1. How to write Content

### Amount of content

The primary measure for amount of content on a page should be based on the purpose it serves.

- Use short pages

Those containing one or two screens of text at most. Users are scanning for link choices. Use longer pages (those that require more scrolling or reading) deeper within the chapter where content can be printed and read later.

- For very large sections of information

Consider creating a supporting document and linking to it from the page rather than displaying all the information directly on the page.

### Timeliness of content

Keeping accurate and timely content establishes the 'Mobile Security Testing Guide' as a credible and trustworthy source of information.

When using statistical data on your page, ensure that the information is current and up-to-date and is accompanied by the source from which it was derived, along with the date the data was compiled.

### Content for the digital platform versus for print

Write concise content that the user can read quickly and efficiently.
For digital content - create shorter pages that are cross-linked. If your content is likely to be printed, create one long page.

### Audience

Write for an international audience with a *basic* level of technical understanding i.e. they have a mobile phone and know how to install an app. Avoid hard-to-translate slang words/phrases to ensure content is accessible to readers who aren't native English speakers.

### Context and orientation

Let the user know where he or she is on every page. Establish the topic by using a unique page heading.

Include a clear and concise introduction where possible.

Link to background information where necessary.

### Write so people will read with joy

Use the following methods to increase scannability:

- Use left alignment for headings, subheadings, and text
- Link where appropriate
- Use lists rather than paragraphs wherever possible
- Use dashes `-` rather than asterisks `*` for lists
- Include only one main idea in each paragraph
- Put the most important information at the top
- Start the page with the conclusion as well as a short summary of the remaining content
- Use headings where applicable
- Use short, simple words that are to the point
- Be concise and focused

For longer pages, use the following tools to make the page easily scannable:

- Anchor links
- Subheadings and relevant links
- Bulleted copy
- Meaningful graphics, or pull quotes, to break up larger blocks of text
- End links

### Effective use of lists

When presenting your content in a list format:

- Use numbered lists when the order of entries is important.
- Use bulleted lists whenever the order of the entries is not important.
- Generally, limit the number of items in a single list to no more than nine.
- Generally, limit lists to no more than two levels: primary and secondary.
- Punctuate and capitalize list items consistently (CMOS 6.124–6.126).
- - Don't add end punctuation to list items that are not complete sentences unless they complete the sentence that introduces the list.
- - Use appropriate capitalization and end punctuation for list items that individually form complete sentences.
- - If the list items complete an introductory sentence, end each (except the last item) with a comma and do not add "and" after the second-to-last item. End the last item with appropriate end punctuation (usu. a period).

### Numbering conventions

When using a number between zero and ten, spell out the number (e.g., "three" or "ten").

When using any number higher than ten, use the numeric version (e.g., "12" or “300”).

## 2. Language

### American spelling and terminology

Use American spelling and terminology.
Change all British spelling and terminology to the American equivalents where applicable. This includes "toward" (US) vs. "towards" (UK), "among" (US) vs. "amongst" (UK), "color" (US) vs "colour" (UK), "flashlight" (US) vs "torch" (UK), etc.

### Plurals

Adhere to standard grammar and punctuation rules when it comes to pluralization of typical words.

The plural of calendar years does not take the apostrophe before the “s.” For example, the plural form of 1990 is 1990s

### Title Capitalization

We follow the title case rules from the "Chicago Manual of Style":  

- Capitalize the first and last word in a title, regardless of part of speech
- Capitalize all nouns (baby, country, picture), pronouns (you, she, it), verbs (walk, think, dream), adjectives (sweet, large, perfect), adverbs (immediately, quietly), and subordinating conjunctions (as, because, although)
- Lowercase “to” as part of an infinitive
- Lowercase all articles (a, the), prepositions (to, at, in, with), and coordinating conjunctions (and, but, or)

When in doubt, you can verify proper capitalization on [www.titlecapitalization.com](http://www.titlecapitalization.com/).

### Standardization

This is a list of words/abbreviations that are used inconsistently at the moment in the MSTG and need standardization:

- man-in-the-middle attack (MITM)

### Contractions

Use the following common contractions:

are not -> aren't  
cannot -> can't  
could not -> couldn't  
did not -> didn't  
do not -> don't  
does not -> doesn't  
has not -> hasn't  
had not -> hadn't  
have not -> haven't  
that is -> that's  
there is -> there's  
was not -> wasn't  
were not -> weren't  
will not -> wont  
would not -> wouldn't  
you are -> you're  
you have + *verb* -> you've + *verb*
you will -> you'll  

### Abbreviations

Spell out abbreviations the first time they are used.

Ex: United States (U.S.)

### Referencing Android versions

Use the following format when referring to an Android version: Android X (API level YY). Usage of the descriptive name (Ex: Oreo) is discouraged.

Ex: Android 9 (API level 28)

### Addressing the reader in test cases

Throughout the guide, you may want to address the reader in order to tell him what to do, or what he should notice. For any such case, use an active approach and simply address the reader using "you".

**Correct:** If you open the AndroidManifest.xml file, you will see a main Application tag, with the following attributes: atr1, atr2 and atr3. If you run the following command, you will see that atr1 is actually dangerous: ...

**Wrong:** The AndroidManifest.xml file contains an Application tag, with the following attributes: atr1, atr2 and atr3. The command below shows that atr1 is dangerous: ...

**Wrong:** If we open the AndroidManifest.xml file, we will see a main Application tag, with the following attributes: atr1, atr2 and atr3. If we run the following command, we will see that atr1 is actually dangerous: ...

## 3. External References

For web links, use the normal markdown in-line link format:

\[TEXT](URL "NAME")

For example:

The [threat modeling guidelines defined by OWASP](https://www.owasp.org/index.php/Application_Threat_Modeling "OWASP Application Threat Modeling") are generally applicable to mobile apps.

These links will be converted to numbered references in the print version.

For books and papers, use the following format.

\[#NAME]

And include the full reference in the "references" section at the end of the markdown file manually. Example:

An obfuscated encryption algorithm can generate its key (or part of the key) using data collected from the environment [#riordan].

And under "references" at the end of the document:

- [#riordan] -  James Riordan, Bruce Schneier. Environmental Key Generation towards Clueless Agents. Mobile Agents and Security, Springer Verlag, 1998

__Papers:__
The general form for citing technical reports is to place the name and location of the company or institution after the author and title and to give the report number and date at the end of the reference.

Basic Format:

- [shortname] J. K. Author, “Title of report,” Abbrev. Name of Co., City of Co., Abbrev. State, Rep. xxx, year

- [shortname] \[Author(s)\], \[Title\] - Link

__Books:__

- [shortname] \[Author(s)\], \[Title\], \[Published\], \[Year\]

- [examplebook] J. K. Author, “Title of chapter in the book,” in Title of His Published Book, xth ed. City of Publisher, Country if not USA: Abbrev. of Publisher, year, ch. x, sec. x, pp. xxx–xxx.

NOTE: Use et al. when three or more names are given

e.g.

- [klaus] B. Klaus and P. Horn, Robot Vision. Cambridge, MA: MIT Press, 1986.
- [stein] L. Stein, “Random patterns,” in Computers and You, J. S. Brake, Ed. New York: Wiley, 1994, pp. 55-70.
- [myer] R. L. Myer, “Parametric oscillators and nonlinear materials,” in Nonlinear Optics, vol. 4, P. G. Harper and B. S. Wherret, Eds. San Francisco, CA: Academic, 1977, pp. 47-160.
- [abramowitz] M. Abramowitz and I. A. Stegun, Eds., Handbook of Mathematical Functions (Applied Mathematics Series 55). Washington, DC: NBS, 1964, pp. 32-33.

## 4. References Within The Guide

For references to other chapters in the MSTG, simply name the chapter, e.g.: `See also the chapter "Basic Security Testing"`, `See the section "Apktool" in the chapter "Basic Security Testing"` etc. The MSTG should be convenient to read as a printed book, so use internal references sparingly. Alternatively you can create a link for the specific section:

```markdown
See the section "[App Bundles](0x05a-Platform-Overview.md#app-bundles)" in the chapter ...
```

Note that in such a case the anchor (everything after the `#`) should be lowercase, and spaces should be replaced with hyphens.

## 5. Insert pictures

Pictures should be uploaded to the Images/Chapters directory. Afterwards they should be embedded by using the image tag, a width of 500px should be specified. For example:

```HTML
<img src="Images/Chapters/0x06d/key_hierarchy_apple.jpg" width="500px"/>
- *iOS Data Protection Key Hierarchy*
```

## 6. Punctuation conventions

### Lowercase or capital letter after a colon

Chicago Manual of Style (6.61: Lowercase or capital letter after a colon) says: lowercase the first word unless it is a proper noun or the start of at least two complete sentences or a direct question.

### Serial comma use

Use a serial comma before "and" for the last item in a run-in list of three or more items. For example:

We bought apples, oranges, and tomatoes from the store.

### Quote Marks and Apostrophes

Use straight double quotes, straight single quotes, and straight apostrophes (not curly quotes/apostrophes).

### Technical Terms

Spell/punctuate **specific** technical terms as they are used by the company (e.g., use the company website).

In order of preference, spell/punctuate **generic** technical terms according to

1. Merriam Webster's Collegiate Dictionary, 11th edition.
2. Microsoft Manual of Style, 4th edition
3. foldoc.org (Free Online Dictionary of Computing)

| Noun Form  | Adjectival Form |
| ---------  | --------------- |
| App Store  |       NA       |
|  back end  |    backend      |
|  Base64    |    Base64-      |
| black box  |     *same*      |
| Bundle ID  |      NA        |
| byte-code  |       NA        |
|client side |  client-side    |
|  codebase  |     *same*      |
|code signing|     *same*      |
|command line|     *same*      |
|disassembler|       NA        |
|  end users |       NA        |
| file name  |     *same*      |
|   macOS    |      NA         |
|   OS X     |      NA         |
|  pentest   |     *same*      |
|  PhoneGap  |       NA        |
|   Python   |       NA        |
| repackage  |       NA        |
|  runtime   |     *same*      |
| server side|   server-side   |
|snapshot length|    NA        |
| use case   |    *same*       |
| white box  |    *same*       |

## 7. Comments

Markdown blockquotes can be used for comments in the documents by using ">"/

> This is a blockquote

## 8. Code and Shell Commands

Use code blocks when including sample code, shell commands, and paths. In Markdown, code blocks are denoted by triple backticks. GitHub also supports syntax highlighting for a variety of languages. For example, a Java code block should be annotated as follows:

```text
    ```java
    public static void main(String[] args) { System.out.println(" Hello World!"); } } ;
    ```
```

This produces the following result:

```java
public static void main(String[] args) { System.out.println(" Hello World!"); } }
```

When including shell commands, make sure to remove any host names and usernames from the command prompt, e.g.:

```shell
$ echo 'Hello World'
Hello World
```

When a command requires parameters that need to be modified by the reader, surround them with angle brackets:

```shell
$ adb pull <remote_file> <target_destination>
```

### In-text keywords

When they do not occur in a code block, place the following code-related keywords in backticks (``), double straight quote marks (""), or leave unpunctuated according to the table:

|    Backticks    | Quotation Marks | No Punctuation |
| --------------- | --------------- | -------------- |
| function names  |  section titles | application name |
|   method names  |  chapter titles | folder names  |
|    commands     |    book titles  | navigation (e.g., Home -> Menu)|
|   class names   | flags values (e.g., "true", lowercase) | ID #s |
|   block names   | command options (e.g., "help" option)||
|   flag names    | single menu item (e.g., "Home" menu)||
|   file names    | system error msgs.|
|  package names  ||
|   file paths    ||
|   passwords     ||
|  port numbers   ||
|   binary names  ||
|method/function arguments||
|method/function argument or return values (e.g., `true`, `0`, `YES`)||
|  XML attributes (e.g., `get-task-allow` on iOS Plists, `"@string/app_name"` on Android Manifests)||
|  XML attribute values (e.g., `android:label` on Android Manifests)||
|  property names ||
|  object names   ||
|    API calls    ||
| interface names ||

If nouns in backticks are plural, place the "s" after the second backtick (e.g. `RuntimeException`s). Do not add parentheses, brackets, or other punctuation to any keywords that are in backticks (e.g., `main` not `main()`).
