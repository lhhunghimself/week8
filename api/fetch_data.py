##! /usr/bin/env python3
#fetch data from the api

import requests, os, json

#get key from environment variable
api_key = os.getenv('API_KEY')

def get_city_coordinates(city, state="WA"):
    """
    Get the longitude and latitude of a city using OpenStreetMap's Nominatim service.
    
    Args:
        city (str): The name of the city
        state (str, optional): The state abbreviation or full name
    
    Returns:
        dict: A dictionary containing latitude and longitude, or None if not found
    """
    base_url = "https://nominatim.openstreetmap.org/search"
    
    # Construct the address query
    address = city
    if state:
        address += f", {state}"
    
    params = {
        "q": address,
        "format": "json",
        "limit": 1
    }
    
    headers = {
        "User-Agent": "YourAppName/1.0"  # Replace with your actual app name/contact info
    }
    
    try:
        response = requests.get(base_url, params=params, headers=headers)
        response.raise_for_status()  # Raise exception for HTTP errors
        
        data = response.json()
        
        # Check if we got valid results
        if data and len(data) > 0:
            # Get the first match
            match = data[0]
            
            return f"{float(match['lat'])},{float(match['lon'])}"
        else:
            print(f"No coordinates found for {address}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching coordinates for {address}: {e}")
        return None


#function to fetch data from the TripAdvisor API given a location
def fetch_tripadvisor_nearby_data(city, state=None, category="restaurants"):
    coordinates = get_city_coordinates(city, state)
    
    # Add error handling for when coordinates are not found
    if coordinates is None:
        print(f"Could not find coordinates for {city}, {state}")
        return {"data": []}  # Return empty data structure
        
    filename = f"{coordinates}_{category}.json"
    #if the file exists get the data from the file
    if os.path.exists(filename):
        print(f"Loading data from {filename}")
        with open(filename, 'r') as f:
            return json.load(f)
    else:
        print(f"Fetching data from TripAdvisor API for {city}, {state}, {category}")
        base_url = "https://api.content.tripadvisor.com/api/v1/location/nearby_search"
        params = {
            "latLong": coordinates,
            "key": api_key,
            "category": category,
            "language": "en"
        }
        #create get request
        response = requests.get(base_url, params=params)
        #write the responset to a file which is the coordinates and the category separated by an underscore
        with open(filename, 'w') as f:
            json.dump(response.json(), f)
        return response.json()

#function to fetch the location details for a given id
def fetch_tripadvisor_location_data(id):
    base_url = f"https://api.content.tripadvisor.com/api/v1/location/{id}/details"
    params = {
            "key": api_key, 
            "language": "en",
            "currency": "USD"
    }
    response = requests.get(base_url, params=params)
    #check if the response is successful
    if response.status_code == 200: 
        return response.json()  
    else:
        print(f"Error fetching data from TripAdvisor API for {id}: {response.status_code}")
        return None

#function to fetch the photos for a given id
def fetch_tripadvisor_photo_data(id):
    base_url = f"https://api.content.tripadvisor.com/api/v1/location/{id}/photos"
    params = {
        "key": api_key,
        "language": "en",
        "limit": 50,
        "offset": 1
        }
    response = requests.get(base_url, params=params)
    if response.status_code == 200: 
        return response.json()  
    else:
        print(f"Error fetching data from TripAdvisor API for {id}: {response.status_code}")
        return None

#test the function with a call to get the location for the city of Seattle
def fetch_tripadvisor_data(city, state="WA", category="restaurants"):
    """
    Fetch TripAdvisor data for a given city and return structured data
    
    Args:
        city (str):     The name of the city
        state (str):    The state abbreviation (default "WA")
        category (str): The category to fetch (default "restaurants")
        
    Returns:
        list: A list of dicts containing photo, name, address, url for each location
    """
    # Get nearby data (now passes category)
    nearby_data = fetch_tripadvisor_nearby_data(city, state, category)
    
    if not nearby_data or 'data' not in nearby_data or not nearby_data['data']:
        print(f"No data found for {city}, {state}, category={category}")
        return []
    
    ids = [item['location_id'] for item in nearby_data['data']]
    
    # ensure top-level dirs exist
    os.makedirs("data/location_details", exist_ok=True)
    os.makedirs("data/photos", exist_ok=True)
    
    trip_advisor_data = []
    
    for id in ids:
        location_info = {}
        
        # —————————————
        # LOCATION DETAILS
        # —————————————
        details_dir  = f"data/location_details/{id}"
        details_file = f"{details_dir}/details_{category}.json"

        if os.path.exists(details_file):
            print(f"Loading location data from {details_file}")
            with open(details_file, 'r') as f:
                location_data = json.load(f)
        else:
            print(f"Fetching location data from TripAdvisor API for {id} (category={category})")
            location_data = fetch_tripadvisor_location_data(id)
            if location_data is not None:
                os.makedirs(details_dir, exist_ok=True)
                with open(details_file, 'w') as f:
                    json.dump(location_data, f)
        
        # pull out the fields we need
        if location_data:
            location_info['name']    = location_data.get('name', '')
            location_info['address'] = location_data.get('address_obj', {}) \
                                                  .get('address_string', '')
            location_info['url']     = location_data.get('web_url', '')
        
        # —————————————
        # PHOTO DATA
        # —————————————
        photos_dir  = f"data/photos/{id}"
        photos_file = f"{photos_dir}/photos_{category}.json"

        if os.path.exists(photos_file):
            print(f"Loading photo data from {photos_file}")
            with open(photos_file, 'r') as f:
                photo_data = json.load(f)
        else:
            print(f"Fetching photo data from TripAdvisor API for {id} (category={category})")
            photo_data = fetch_tripadvisor_photo_data(id)
            if photo_data is not None:
                os.makedirs(photos_dir, exist_ok=True)
                with open(photos_file, 'w') as f:
                    json.dump(photo_data, f)
        
        # pick first thumbnail (if any)
        if photo_data and 'data' in photo_data and photo_data['data']:
            location_info['photo'] = photo_data['data'][0] \
                                     .get('images', {}) \
                                     .get('thumbnail', {}) \
                                     .get('url', '')
        else:
            location_info['photo'] = ''
        
        trip_advisor_data.append(location_info)
    
    return trip_advisor_data

#add main function to fetch the data
if __name__ == "__main__":
    fetch_tripadvisor_data("Seattle", "WA")






