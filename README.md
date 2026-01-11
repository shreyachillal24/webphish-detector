🛡️ WebPhish Detector

WebPhish Detector is a web-based phishing detection system that uses Machine Learning and security heuristics to identify malicious, legitimate, and invalid website URLs.
The system provides real-time detection along with clear explanations for every prediction.

📌 Problem Statement

Phishing attacks are one of the most common cybersecurity threats today. Attackers create fake websites that closely resemble legitimate ones to steal sensitive information such as login credentials and banking details.
Traditional blacklist-based systems fail to detect newly created phishing websites, making users vulnerable to cyber fraud.

💡 Solution Overview

WebPhish Detector solves this problem using a hybrid approach:

Machine Learning to detect hidden phishing patterns

Rule-based security heuristics for high-risk indicators

Explainable output to improve user trust and awareness

✨ Key Features

🔍 Machine learning-based phishing detection

🔗 URL and domain-based feature analysis

⚙️ Hybrid ML + heuristic decision logic

🧠 Explainable phishing detection results

🌐 Flask-based web application

⚡ Real-time URL verification

🧠 Machine Learning Model

Model Used: Random Forest Classifier

Library: Scikit-learn

Reason:

Works well with structured URL features

Reduces overfitting

Provides stable and accurate classification

📊 Dataset Information

Dataset Source: Public phishing website dataset by Grega Vrbančič

Available on: GitHub / Mendeley Data

Data Type: Labeled phishing and legitimate URLs

Features: URL-based and domain-based characteristics

🏗️ System Architecture
User
 ↓
Web Interface (HTML/CSS)
 ↓
Flask Server
 ↓
Feature Extraction
 ↓
ML Model + Security Heuristics
 ↓
Prediction + Explanation

🛠️ Technologies Used

Programming Language: Python

Web Framework: Flask

Machine Learning: Scikit-learn

Data Processing: Pandas, NumPy

Frontend: HTML, CSS

Version Control: Git & GitHub

🚀 How to Run the Project Locally
1️⃣ Clone the Repository
git clone https://github.com/shreyachillal24/webphish-detector.git
cd webphish-detector

2️⃣ Create Virtual Environment (Optional but Recommended)
python -m venv venv
venv\Scripts\activate   # Windows

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Run the Application
python app/app.py

5️⃣ Open in Browser
http://127.0.0.1:5000

📈 Output

Phishing Website → Flagged with high-risk indicators

Legitimate Website → Safe with no phishing patterns detected

Invalid URL → Rejected with validation error

Explainable Reasons → Displayed for every decision

⚠️ Limitations

URL-based detection only

Does not analyze webpage visual similarity

Email phishing detection not included

🔮 Future Enhancements

Email phishing detection

Browser extension for real-time protection

Deep learning-based detection models

Webpage content and visual similarity analysis

Integration with real-time threat intelligence APIs

🎓 Academic Relevance

This project was developed as a 7th Semester Computer Science Engineering project, demonstrating the practical application of:

Machine Learning

Cybersecurity concepts

Web application development
