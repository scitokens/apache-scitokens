import requests

# api-endpoint
URL = "http://URL/demo"

# location given here
location = "scitoken 1234"

# defining a params dict for the parameters to be sent to the API
headers = {'Authorization':location}

# sending get request and saving the response as response object
r = requests.get(url = URL, headers = headers)

# extracting data in json format
#data = r.json()


# extracting latitude, longitude and formatted address
# of the first matching location
#latitude = data['results'][0]['geometry']['location']['lat']
#longitude = data['results'][0]['geometry']['location']['lng']
#formatted_address = data['results'][0]['formatted_address']

# printing the output
print(r)
