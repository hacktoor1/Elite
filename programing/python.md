# Python

**1. Print Statement**

Copy

```
print("Hello, World!")
```

**2. Variables and Data Types**

Copy

```
age = 25
name = "John"
is_student = True
```

**3. String Formatting**

Copy

```
greeting = f"Hello, {name}! You are {age} years old."
```

**4. Lists and Indexing**

Copy

```
my_list = [1, 2, 3, "four", 5.0]
first_item = my_list[0]
```

**5. Dictionaries**

Copy

```
my_dict = {"key": "value", "name": "Alice"}
value = my_dict["key"]
```

**6. Conditional Statements**

Copy

```
if age > 18:
    print("You are an adult.")
elif age == 18:
    print("You just became an adult.")
else:
    print("You are a minor.")
```

**7. Loops - For and While**

Copy

```
for i in range(5):
    print(i)

counter = 0
while counter < 5:
    print(counter)
    counter += 1
```

**8. Functions**

Copy

```
def greet(person):
    return f"Hello, {person}!"

result = greet("Bob")
```

**9. List Comprehensions**

Copy

```
squared_numbers = [x**2 for x in range(5)]
```

**10. Exception Handling**

Copy

```
try:
    result = 10 / 0
except ZeroDivisionError:
    result = "Cannot divide by zero."
```

**11. Classes and Objects**

Copy

```
class Dog:
    def __init__(self, name):
        self.name = name

my_dog = Dog("Buddy")
```

**12. File Handling**

Copy

```
with open("file.txt", "r") as file:
    content = file.read()
```

**13. Modules and Libraries**

Copy

```
import math
sqrt_result = math.sqrt(25)
```

**14. Lambda Functions**

Copy

```
multiply = lambda x, y: x * y
product = multiply(3, 4)
```

**15. Working with JSON**

Copy

```
import json

data = '{"name": "John", "age": 25}'
user_info = json.loads(data)
```

**16. Modules and Libraries**

Copy

```
import random
random_number = random.randint(1, 10)
```

**17. Working with Files**

Copy

```
with open("new_file.txt", "w") as new_file:
    new_file.write("This is a new file.")
```

**18. Exception Handling (try, except, else, finally)**

Copy

```
try:
    result = 10 / 2
except ZeroDivisionError:
    result = "Cannot divide by zero."
else:
    print(f"Result: {result}")
finally:
    print("Execution complete.")
```

**19. Classes and Inheritance**

Copy

```
class Animal:
    def speak(self):
        return "Some generic sound."

class Dog(Animal):
    def speak(self):
        return "Woof!"

my_animal = Animal()
my_dog = Dog()

animal_sound = my_animal.speak()
dog_sound = my_dog.speak()
```

**20. List Manipulation**

Copy

```
numbers = [1, 2, 3, 4, 5]
numbers.append(6)
numbers.pop(2)
```

**21. Sets**

Copy

```
my_set = {1, 2, 3, 4, 5}
my_set.add(6)
```

**22. Tuples**

Copy

```
coordinates = (3, 4)
x, y = coordinates
```

**23. Working with Dates and Times**

Copy

```
from datetime import datetime

current_time = datetime.now()
formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
```

**24. List Sorting**

Copy

```
numbers = [4, 2, 7, 1, 9]
sorted_numbers = sorted(numbers)
```

**25. Map, Filter, and Reduce**

Copy

```
numbers = [1, 2, 3, 4, 5]
squared_numbers = list(map(lambda x: x**2, numbers))
even_numbers = list(filter(lambda x: x % 2 == 0, numbers))
sum_of_numbers = functools.reduce(lambda x, y: x + y, numbers)
```

**26. Virtual Environments**

Copy

```
# Create virtual environment
python -m venv myenv

# Activate virtual environment
source myenv/bin/activate  # On Linux/Mac
myenv\Scripts\activate      # On Windows

# Deactivate virtual environment
deactivate
```

**27. Working with APIs**

Copy

```
import requests
response = requests.get("https://jsonplaceholder.typicode.com/todos/1")
data = response.json()
```

**28. Regular Expressions**

Copy

```
import re
pattern = re.compile(r'\b(\w+)\b')
matches = pattern.findall("This is a sample sentence.")
```

**29. Lambda Functions**

Copy

```
square = lambda x: x**2
result = square(5)
```

**30. List Comprehensions**

Copy

```
squares = [x**2 for x in range(5)]
```

**31. Dictionary Manipulation**

Copy

```
my_dict = {'a': 1, 'b': 2, 'c': 3}
my_dict['d'] = 4
del my_dict['b']
```

**32. JSON Manipulation**

Copy

```
import json

# Convert Python object to JSON string
json_data = json.dumps({'name': 'John', 'age': 30})

# Convert JSON string to Python object
python_object = json.loads('{"name": "John", "age": 30}')
```

**33. Context Managers**

Copy

```
with open('file.txt', 'r') as file:
    content = file.read()
# File is automatically closed outside the block
```

**34. Decorators**

Copy

```
def my_decorator(func):
    def wrapper():
        print("Something is happening before the function is called.")
        func()
        print("Something is happening after the function is called.")
    return wrapper

@my_decorator
def say_hello():
    print("Hello!")

say_hello()
```

**35. Asyncio (Asynchronous Programming)**

Copy

```
import asyncio

async def my_coroutine():
    print("Coroutine started.")
    await asyncio.sleep(1)
    print("Coroutine completed.")

# Run the coroutine
asyncio.run(my_coroutine())
```

**36. Web Scraping with BeautifulSoup**

Copy

```
from bs4 import BeautifulSoup
import requests

url = "https://example.com"
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')
```

**37. Machine Learning with Scikit-Learn**

Copy

```
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression

# Assuming X and y are your features and target variable
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
model = LinearRegression()
model.fit(X_train, y_train)
```

**38. Django Web Framework**

Copy

```
# Install Django
pip install Django

# Create a new Django project
django-admin startproject myproject

# Run the development server
python manage.py runserver
```

**39. Flask Web Framework**

Copy

```
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'
```

**40. Creating a Simple REST API with Flask-RESTful**

Copy

```
from flask import Flask
from flask_restful import Resource, Api

app = Flask(__name__)
api = Api(app)

class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}

api.add_resource(HelloWorld, '/')
```
