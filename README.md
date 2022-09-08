# Malware Detection using machine learning (MDML)

## Deployed application

https://mdml.herokuapp.com/

Deployed on a free Heroku instance, thus, the performance is not amazing but should serve its purpose as a PoC.

## Running it locally

streamlit run app.py

## Author

Mohamed Benchikh
## Analysis modules: 
- **Static**: Features are extracted from PE file headers (mainly Optional Header)
![Static Analysis](https://user-images.githubusercontent.com/58364955/188492453-8ee68af8-1cf5-4192-a03f-56d472c243c2.png)

- **Dynamic**: Features are the API calls traced using Cuckoo Sandbox
![Dynamic Analysis](https://user-images.githubusercontent.com/58364955/188492663-6f25ca0a-f8e1-4e1f-8810-58e4d8799821.png)

## Datasets construction
- **Static**

Malware samples were acquired from MalwareBazaar while benign samples were acquired from multiple online hosting websites (ie. CNET)
we then used pefile module in Python to parse PE headers and extract relevant features (chosen using benchmarks), we also used Yara capabilities, digital signature, and packing as features 

- **Dynamic**

we tweaked the APIMDS dataset from hksecurity and changed it from a dataset of API calls sequences to a dataset of binary values with predetermined features

## Algorithm used

We compared multiple algorithms using a 10-Fold stratified cross validation process algorithm, we settled on Extreme Gradient Boosting (XGBoost) classification algorithm as it had the highest F1 score

## Project interfaces

### Static
![Static interface](https://user-images.githubusercontent.com/58364955/188493379-e5cc0e6c-28db-4732-8acb-08b6d586cc83.png)
### Dynamic
![Dynamic interface](https://user-images.githubusercontent.com/58364955/188493424-bc971958-09bd-415f-afd7-632dfb85f310.png)
