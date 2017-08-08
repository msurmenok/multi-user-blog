# Multi User Blog
Multi user blog with registration and ability to comment and like posts.

Running version on https://multi-user-blog-165621.appspot.com/

## Prerequisites
[Python 2.7](https://www.python.org/downloads/)
[Google Cloud SDK](https://cloud.google.com/sdk/docs/)

## Quickstart
(based on [Quickstart from Google](https://cloud.google.com/appengine/docs/standard/python/quickstart) and [Udacity instructions](https://drive.google.com/file/d/0Byu3UemwRffDbjd0SkdvajhIRW8/view))

- Create a new project on [Cloud Platform Console](https://console.cloud.google.com/projectselector/appengine/create?lang=python)
- Download project `git clone https://github.com/msurmenok/multi-user-blog.git`
- Change directory to the project `cd multi-user-blog`

**To run application on your local machine:**

- `dev_appserver.py .`
- or if it doesn't work, try `python "C:\Users\<YOUR USERNAME>\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\dev_appserver.py" .`
- application will start on http://localhost:8080/ with admin server on http://localhost:8000/

**To deploy project in cloud:**
- `gcloud app deploy`
- if you have some troubles with indexing, from the directory with the project run `gcloud datastore create-indexes index.yaml`

## Preview
![multi user blog preview](/preview1.png?raw=true)
##
![multi user blog preview](/preview2.png?raw=true)

## License
Code released under the [MIT License](https://github.com/msurmenok/multi-user-blog/blob/master/LICENSE)
