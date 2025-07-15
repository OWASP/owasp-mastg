import json
import requests

url = 'https://api.github.com/repos/OWASP/mastg/stats/contributors'
headers = {'Accept' : 'application/vnd.github.v3+json'}

r = requests.get(url, headers=headers)

data = r.json()

coAuthor = "Author/Co-Authors: "
topContributors = "Top Contributors: "
contributors = "Contributors: "
miniContributors = "Mini Contributors: "
additions = ''

for authors in data[:]:
    # print(authors['weeks'])
    # print(authors['author']['login'])
    # print(authors['weeks'])

    count = 0

    # count additions for each author
    for allWeeks in authors['weeks']:
        count += allWeeks['a']

    if (count >= 2000):
        # author = "Co-Author: "+authors['author']['login']
        # additions = author + " Additions:" + str(count)
        # print(additions)
        coAuthor += authors['author']['login']+", "
    elif ((count >= 500) and (count <2000)):
        # author = "Top Contributors: "+authors['author']['login']
        # additions = author + " Additions:" + str(count)
        # print(additions)
        topContributors += authors['author']['login']+", "
    elif ((count >= 50) and (count <500)):
        # author = "Contributors: "+authors['author']['login']
        # additions = author + " Additions:" + str(count)
        # print(additions)
        contributors += authors['author']['login']+", "
    elif ((count >= 1) and (count <50)):
        # author = "Mini Contributors: "+authors['author']['login']
        # additions = author + " Additions:" + str(count)
        # print(additions)
        miniContributors += authors['author']['login']+", "
        

print(coAuthor+"\n")
print(topContributors+"\n")
print(contributors+"\n")
print(miniContributors+"\n")