# ioctool
Despite having MISPs and similar products around, you might occassionally come to the point where you get IOCs (indicators of compromise) sent to you in an unstructured format like an email body, a text file, an excel spreadsheet and so on.
So I wrote a script that usese regex to carve the most common indicator types (IP, MD5, SHA1, SHA256, URL) directly out of your clipboard. That way, you can just Ctrl+A/Ctrl+C the whole text and then run `ioctool` - done.

## Usage
```
# Load into your current powershell host
. ioctool.ps1

# Use Ctrl+C to copy the text containing IOCs into your clipboard, then run ioctool
ioctool

# The script will automatically carve indicators out of the text and show you a summary. You can then write everything or only selected types of indicators back to the clipboard and move on from there.
```
## Example
Let's take [this article by CISA on QakBot](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-242a) as an example. CISA also provides their indicators in STIX format but let's assume you'd only have the article. It contains a bunch of defanged IPs and one SHA256 hash. Using ioctool, you can carve the website and extract the indicators quickly.

Just Ctrl+A/Ctrl+C the whole site and run ioctool.

![Screenshot 2024-01-23 124441](https://github.com/cfalta/ioctool/assets/7213829/a373c418-8d2e-4157-b2ca-9068f5802299)


