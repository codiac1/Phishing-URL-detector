# Phishing URL Detection
This is a machine learning project built in Python for detecting phishing URLs. The project uses a dataset containing URLs marked as phishing, risky, and legitimate and trains several models using ensemble learning techniques. The best performing model, Random Forest, is then used to make predictions with live URLs.

## Feature Extraction:
The feature extraction process involves detecting key features of the URLs, such as URL length, the presence of IPv4 or IPv6, the use of HTTPS, the number of protocols, and the top-level domain (TLD) extension. These features are then used to train the machine learning models.

## Models Used:
The following models were used in this project:

* Random Forest
* K-Nearest Neighbors (KNN) Algorithm
* AdaBoost Classifier
* Extra Trees Classifier
* Stochastic Gradient Descent (SGD) Classifier
* Gaussian Naive Bayes

## Results:
After comparing the results of the different models, it was found that the Random Forest model gave the best accuracy. As a result, the Random Forest model was used for the final predictions.

## Usage :
The project requires the following libraries to be installed:

* pandas
* numpy
* scikit-learn
* matplotlib

## To Run :
To run the project, simply clone the repository and run the main script in a Python environment.

## Conclusion
This project demonstrates the use of machine learning techniques for detecting phishing URLs. The feature extraction process and the use of the Random Forest model were found to be effective in detecting phishing URLs with high accuracy.
