# AI-Based Network Intrusion Detection System (NIDS)

## Project Overview

This project implements a **Machine Learning–based Network Intrusion Detection System (NIDS) prototype** using the **CIC-IDS2017 dataset**.
The system is designed to classify network traffic as **Benign** or **Attack** based on flow-level features.

The project focuses on demonstrating:

* Feature-based intrusion detection
* Supervised machine learning for cybersecurity
* Model evaluation using standard metrics
* A web-based dashboard for interaction and visualization



## Important Clarification (Read This First)

This project is a **prototype and academic demonstration**, not a production-ready real-time NIDS.

* ✅ Uses **benchmark network flow data (CIC-IDS2017)**
* ❌ Does **not** capture live packets from the network
* ❌ Does **not** perform real-time packet sniffing
* ❌ Online deployment runs in **demo mode** due to dataset size limits

These design choices were made intentionally to keep the project feasible and evaluable in an academic setting.



## Dataset

* **Name:** CIC-IDS2017
* **Source:** Canadian Institute for Cybersecurity (UNB)
* **Type:** Flow-based CSV files generated using CICFlowMeter
* **Features:** Network flow statistics such as duration, packet counts, and traffic rates
* **Labels:** BENIGN and various attack types (converted to binary: Benign / Attack)

> Note: The dataset is **not included in this repository** because the CSV files exceed GitHub size limits.
> Model training is performed **locally**, while the deployed app runs in demo mode.



## Machine Learning Approach

* **Algorithm:** Random Forest Classifier
* **Classification Type:** Binary (Benign vs Attack)
* **Preprocessing:**

  * Removal of missing and infinite values
  * Feature scaling using StandardScaler
* **Evaluation Metrics:**

  * Accuracy
  * Precision
  * Recall
  * F1-Score
  * Confusion Matrix



## Application Features

### 1. Model Training (Local)

* Loads CIC-IDS2017 CSV data
* Trains a Random Forest model
* Evaluates performance on a test split

### 2. Manual Traffic Test (Demo Mode)

* Allows users to manually input selected network flow parameters:

  * Flow Duration
  * Total Forward Packets
  * Total Backward Packets
  * Flow Bytes per second
  * Flow Packets per second
* The trained model predicts whether the input traffic is:

  * ✅ Benign
  * ⚠️ Attack

> This manual input simulates flow-level behavior and is intended **only for demonstration**, not real network monitoring.



## Deployment

* **Platform:** Streamlit Community Cloud
* **Repository:** GitHub
* **Status:** Demo-only deployment

Due to dataset size constraints, the deployed version does **not** retrain the model online.
All full training and experimentation are performed locally.



## Technologies Used

* Python
* Pandas, NumPy
* Scikit-learn
* Streamlit
* Matplotlib, Seaborn



## Limitations

* No real-time packet capture
* No encrypted traffic analysis
* No zero-day attack detection
* Performance depends on dataset quality and class balance



## Future Enhancements

* Integration with live packet capture tools (Scapy / PyShark)
* Anomaly-based intrusion detection (Autoencoders)
* Multi-class attack classification
* Deployment with external data storage for large datasets



## Conclusion

This project demonstrates how machine learning can be applied to network intrusion detection using benchmark datasets. While not a production NIDS, it provides a solid foundation for understanding intrusion detection concepts, ML workflows, and cybersecurity evaluation techniques.



