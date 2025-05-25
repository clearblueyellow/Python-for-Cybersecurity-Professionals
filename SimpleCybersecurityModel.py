
import sqlite3
import pandas as pd
import numpy as np
import json
import re
import joblib # For saving/loading model and preprocessor
from urllib.parse import urlparse
import math # For entropy calculation

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
# from sklearn.feature_extraction.text import TfidfVectorizer # Keep for future use

# --- Configuration ---
DB_NAME = "threat_intelligence.db"
MODEL_PIPELINE_OUTPUT_PATH = "cybersecurity_threat_pipeline_v2.joblib" # Saves preprocessor + model

LABELING_CONFIG = {
    "vt_min_detections_strong": 10, # Threshold for strong malicious signal from VirusTotal
    "vt_min_detections_moderate": 3,
    "abuseipdb_min_score_strong": 90, # Threshold for strong malicious signal from AbuseIPDB
    "abuseipdb_min_score_moderate": 75,
    "malicious_keywords": ['malware', 'phishing', 'c2', 'botnet', 'compromised', 'exploit', 'ransomware', 'trojan', 'spyware', 'keylogger', 'credential harvesting', 'drive-by'],
    "min_sources_for_malicious_if_keywords": 1, # If keywords present, how many sources needed
    "min_sources_for_malicious_if_moderate_signal": 2, # If moderate VT/AbuseIPDB signal, how many sources
}

# --- 1. Data Loading ---
def load_data_from_db(db_path=DB_NAME, query="SELECT * FROM aggregated_threats ORDER BY RANDOM() LIMIT 20000"): # Increased limit & random sample
    """Loads data from the SQLite database into a pandas DataFrame."""
    print(f"Loading data from {db_path}...")
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query(query, conn)
        conn.close()
        print(f"Loaded {len(df)} records.")
        # Attempt to parse raw_data and tags immediately after loading
        def safe_json_loads(json_str):
            if pd.isna(json_str): return None
            try: return json.loads(json_str)
            except (json.JSONDecodeError, TypeError): return None # Or return the string itself if preferred

        if 'raw_data' in df.columns:
            df['raw_data_dict'] = df['raw_data'].apply(safe_json_loads)
        if 'tags' in df.columns:
            df['tags_list'] = df['tags'].apply(safe_json_loads)

        return df
    except sqlite3.Error as e:
        print(f"Database Error: Failed to load data: {e}")
        return pd.DataFrame()
    except Exception as e:
        print(f"An unexpected error occurred during data loading: {e}")
        return pd.DataFrame()

# --- 2. Robust Labeling Strategy ---
def apply_robust_labeling_strategy(df, config=LABELING_CONFIG):
    print("Applying robust labeling strategy...")
    if df.empty:
        print("DataFrame is empty, cannot apply labels.")
        return df

    df['is_malicious'] = 0 # Default to not malicious

    # Calculate num_sources once
    if 'ioc_value' in df.columns and 'source_provider' in df.columns:
        df['num_sources'] = df.groupby('ioc_value')['source_provider'].transform('nunique')
    else:
        print("Warning: 'ioc_value' or 'source_provider' column not found for source count calculation.")
        df['num_sources'] = 1


    for index, row in df.iterrows():
        is_mal_flag = 0
        raw_data = row.get('raw_data_dict', {}) if pd.notna(row.get('raw_data_dict')) else {}
        tags_list = row.get('tags_list', []) if isinstance(row.get('tags_list'), list) else []
        num_sources = row.get('num_sources', 1)

        # Rule 1: High/Moderate Confidence from Specific Providers
        if row['source_provider'] == 'VirusTotal' and raw_data:
            vt_stats = raw_data.get('last_analysis_stats', {})
            if isinstance(vt_stats, dict): # Ensure vt_stats is a dict
                malicious_detections = vt_stats.get('malicious', 0)
                if malicious_detections >= config['vt_min_detections_strong']:
                    is_mal_flag = 1
                elif malicious_detections >= config['vt_min_detections_moderate'] and num_sources >= config['min_sources_for_malicious_if_moderate_signal']:
                    is_mal_flag = 1
        
        if is_mal_flag == 0 and row['source_provider'] == 'AbuseIPDB' and raw_data:
            abuse_score = raw_data.get('abuseConfidenceScore', 0)
            if abuse_score >= config['abuseipdb_min_score_strong']:
                is_mal_flag = 1
            elif abuse_score >= config['abuseipdb_min_score_moderate'] and num_sources >= config['min_sources_for_malicious_if_moderate_signal']:
                is_mal_flag = 1

        # Rule 2: Malicious Keywords in Tags (if not already flagged)
        if is_mal_flag == 0 and tags_list:
            for tag_item in tags_list:
                tag_str = str(tag_item).lower() # Ensure tag is string and lowercase
                if any(keyword in tag_str for keyword in config['malicious_keywords']):
                    if num_sources >= config['min_sources_for_malicious_if_keywords']:
                        is_mal_flag = 1
                        break
        
        # Rule 3: Multiple Sources (as a general indicator if other signals are weak)
        # This rule is now implicitly handled by the num_sources checks in Rule 1 and 2.
        # We could add a standalone rule:
        # if is_mal_flag == 0 and num_sources >= config.get('min_sources_standalone', 3):
        # is_mal_flag = 1

        df.loc[index, 'is_malicious'] = is_mal_flag

    malicious_count = df['is_malicious'].sum()
    total_count = len(df)
    benign_count = total_count - malicious_count
    print(f"Labeling complete. Malicious samples: {malicious_count} ({malicious_count/total_count:.2%}), Benign samples: {benign_count} ({benign_count/total_count:.2%})")
    if malicious_count == 0 or benign_count == 0:
        print("Warning: All samples are labeled as a single class. This will likely lead to poor model training or errors.")
    return df

# --- 3. Feature Engineering ---
def shannon_entropy(s):
    if not s: return 0
    p, lns = {}, float(len(s))
    for c in s:
        p[c] = p.get(c, 0) + 1
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def get_tld(domain_or_url):
    if pd.isna(domain_or_url): return 'unknown'
    try:
        parsed_url = urlparse(str(domain_or_url))
        hostname = parsed_url.hostname if parsed_url.hostname else parsed_url.path # Handle cases where input is just domain
        if hostname:
            parts = hostname.split('.')
            if len(parts) > 1 and parts[-1] != '': # Ensure there's something after the last dot
                # Simple TLD extraction, might not cover all multi-part TLDs like .co.uk perfectly
                return parts[-1] 
    except Exception:
        pass
    return 'unknown'

def engineer_features_v2(df):
    print("Engineering features (v2)...")
    if df.empty:
        print("DataFrame is empty, cannot engineer features.")
        return df, None

    # Initialize new feature columns to avoid KeyError later if conditions not met
    df['ioc_length'] = 0
    df['ioc_special_chars'] = 0
    df['url_domain_entropy'] = 0.0
    df['url_path_depth'] = 0
    df['url_query_params_count'] = 0
    df['url_tld'] = 'unknown'
    df['url_contains_ip_address'] = 0
    df['ip_is_private'] = 0
    df['vt_detection_count'] = 0 # From raw_data
    df['abuseipdb_score_feat'] = 0 # From raw_data

    # Feature from IOC value
    if 'ioc_value' in df.columns and 'ioc_type' in df.columns:
        df['ioc_length'] = df['ioc_value'].astype(str).apply(len)
        df['ioc_special_chars'] = df['ioc_value'].astype(str).apply(lambda x: len(re.findall(r'[^a-zA-Z0-9\s./:?=&-]', x)))

        for index, row in df.iterrows():
            ioc_val = str(row['ioc_value'])
            ioc_type = str(row['ioc_type']).lower()
            raw_data_dict = row.get('raw_data_dict', {}) if pd.notna(row.get('raw_data_dict')) else {}

            if ioc_type in ['url', 'domain']:
                try:
                    parsed_url = urlparse(ioc_val)
                    domain = parsed_url.hostname if parsed_url.hostname else parsed_url.path # Handle if only domain
                    if domain:
                        df.loc[index, 'url_domain_entropy'] = shannon_entropy(domain)
                        df.loc[index, 'url_tld'] = get_tld(domain)
                    
                    df.loc[index, 'url_path_depth'] = len(parsed_url.path.strip('/').split('/')) if parsed_url.path.strip('/') else 0
                    df.loc[index, 'url_query_params_count'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
                    df.loc[index, 'url_contains_ip_address'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ioc_val) else 0
                except Exception: pass # Ignore parsing errors for malformed URLs

            elif ioc_type == 'ipv4' or ioc_type == 'ip_address' or ioc_type == 'ip': # Handle variations
                try:
                    ip_parts = list(map(int, ioc_val.split('.')))
                    if len(ip_parts) == 4:
                        if (ip_parts[0] == 10 or
                            (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or
                            (ip_parts[0] == 192 and ip_parts[1] == 168)):
                            df.loc[index, 'ip_is_private'] = 1
                except ValueError: pass # Not a valid IP format

            # Extract numerical features from raw_data
            if row.get('source_provider') == 'VirusTotal' and raw_data_dict:
                vt_stats = raw_data_dict.get('last_analysis_stats', {})
                if isinstance(vt_stats, dict):
                    df.loc[index, 'vt_detection_count'] = vt_stats.get('malicious', 0)

            if row.get('source_provider') == 'AbuseIPDB' and raw_data_dict:
                df.loc[index, 'abuseipdb_score_feat'] = raw_data_dict.get('abuseConfidenceScore', 0)
    else:
        print("Warning: 'ioc_value' or 'ioc_type' not found for main feature engineering.")


    # Num sources (already calculated for labeling, can be reused)
    if 'num_sources' not in df.columns: # Should be present from labeling step
        if 'ioc_value' in df.columns and 'source_provider' in df.columns:
            df['num_sources'] = df.groupby('ioc_value')['source_provider'].transform('nunique')
        else:
            df['num_sources'] = 1


    numerical_features = [
        'ioc_length', 'ioc_special_chars', 'num_sources',
        'url_domain_entropy', 'url_path_depth', 'url_query_params_count',
        'url_contains_ip_address', 'ip_is_private',
        'vt_detection_count', 'abuseipdb_score_feat'
    ]
    # Ensure all numerical features are actually present and numeric, fill NaNs
    for nf in numerical_features:
        if nf not in df.columns: df[nf] = 0 # Add if missing
        df[nf] = pd.to_numeric(df[nf], errors='coerce').fillna(0)


    categorical_features = ['ioc_type', 'source_provider', 'url_tld']
    for cat_col in list(categorical_features): # Iterate over a copy for safe removal
        if cat_col not in df.columns:
            print(f"Warning: Categorical feature '{cat_col}' not found. It will be ignored.")
            categorical_features.remove(cat_col)
        else:
            df[cat_col] = df[cat_col].fillna('Unknown').astype(str)


    print(f"Final numerical features for model: {numerical_features}")
    print(f"Final categorical features for model: {categorical_features}")

    # Define preprocessor
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_features),
            ('cat', OneHotEncoder(handle_unknown='ignore', min_frequency=0.01, sparse_output=False), categorical_features) # min_frequency to handle rare categories
        ],
        remainder='drop'
    )
    
    if 'is_malicious' not in df.columns:
        print("Error: Target variable 'is_malicious' not found. Cannot proceed.")
        return pd.DataFrame(), None, None, None

    X = df.drop('is_malicious', axis=1, errors='ignore')
    y = df['is_malicious']
    
    print("Fitting preprocessor and transforming features...")
    try:
        X_processed = preprocessor.fit_transform(X)
        print(f"Processed feature shape: {X_processed.shape}")
        
        # Get feature names after one-hot encoding
        try:
            ohe_feature_names = preprocessor.named_transformers_['cat'].get_feature_names_out(categorical_features)
            all_feature_names = numerical_features + list(ohe_feature_names)
            print(f"Total features after preprocessing: {len(all_feature_names)}")
        except Exception as e_fn:
            print(f"Could not get detailed feature names: {e_fn}")
            all_feature_names = None
            
        return X_processed, y, preprocessor, all_feature_names
    except ValueError as ve:
        print(f"ValueError during preprocessing: {ve}. Check feature lists and data types.")
        return pd.DataFrame(), y, None, None
    except Exception as e:
        print(f"An unexpected error occurred during feature preprocessing: {e}")
        return pd.DataFrame(), y, None, None

# --- 4. Model Training (Unchanged) ---
def train_model(X_train, y_train, model_type='random_forest'):
    print(f"Training {model_type} model...")
    if model_type == 'random_forest':
        model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced_subsample', min_samples_leaf=5)
    elif model_type == 'logistic_regression':
        model = LogisticRegression(random_state=42, class_weight='balanced', max_iter=1000, solver='liblinear')
    else:
        raise ValueError("Unsupported model type.")
    
    model.fit(X_train, y_train)
    print("Model training complete.")
    return model

# --- 5. Model Evaluation (Unchanged) ---
def evaluate_model(model, X_test, y_test, feature_names=None):
    print("Evaluating model...")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1] # Proba for positive class
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    # Added target_names for clarity if classes are 0 and 1
    print(classification_report(y_test, y_pred, target_names=['Benign (0)', 'Malicious (1)'], zero_division=0))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    # Consider plotting confusion matrix for better visualization
    # import seaborn as sns
    # sns.heatmap(cm, annot=True, fmt='d', xticklabels=['Benign', 'Malicious'], yticklabels=['Benign', 'Malicious'])
    # plt.ylabel('Actual')
    # plt.xlabel('Predicted')
    # plt.show()

    if hasattr(model, 'feature_importances_') and feature_names:
        print("\nTop 15 Feature Importances:")
        importances = model.feature_importances_
        feature_importance_df = pd.DataFrame({'feature': feature_names, 'importance': importances})
        feature_importance_df = feature_importance_df.sort_values(by='importance', ascending=False).head(15)
        print(feature_importance_df)

# --- 6. Prediction on New Data (Using full pipeline) ---
def predict_with_pipeline(data_df, pipeline):
    """
    Makes predictions on new, unseen data using the loaded pipeline (preprocessor + model).
    'data_df' should be a DataFrame with the same raw column structure as the original training data.
    """
    print("Predicting on new data with loaded pipeline...")
    if pipeline is None:
        print("Error: Pipeline (preprocessor + model) is not loaded.")
        return None, None
    if data_df.empty:
        print("Input DataFrame for prediction is empty.")
        return None, None

    # The pipeline's preprocessor step will handle feature transformation.
    # We need to ensure the input `data_df` has the necessary raw columns.
    # The feature engineering steps (like creating 'url_tld', 'ip_is_private', etc.)
    # that were done *before* fitting the preprocessor also need to be applied to `data_df`.
    
    # Re-apply the same initial feature engineering to the new data
    # This is a bit tricky as engineer_features_v2 fits the preprocessor.
    # Ideally, feature creation logic should be separable from preprocessor fitting.
    # For now, let's assume data_df comes in a state where it *can* be processed by the *fitted* preprocessor.
    # This means it needs the columns the preprocessor was trained on.
    
    # A better approach:
    # 1. Create a function that does ONLY the raw feature creation (e.g., create_raw_features(df)).
    # 2. Call this on training data before fitting the preprocessor.
    # 3. Call this on new data before pipeline.predict().

    # Quick fix for this example: Re-run parts of engineer_features_v2 that create columns
    # This is not ideal as it duplicates logic.
    # A cleaner way is to have a dedicated feature creation function.
    
    # --- Re-apply necessary feature creations (simplified for this example) ---
    # This part needs to be robust and match what was done during training.
    # The pipeline itself expects the output of these initial transformations.
    
    # For simplicity, let's assume `data_df` is already in the state *just before* `preprocessor.fit_transform`
    # was called on the training data. This means it has 'ioc_type', 'source_provider', 'url_tld', etc.
    # The `engineer_features_v2` function as written now does this transformation and preprocessor fitting.
    # For prediction, we ONLY want the transformation part of the preprocessor.
    
    # The `pipeline` object (preprocessor + model) handles this.
    # We just need to ensure `data_df` has the initial raw columns.
    # The `engineer_features_v2` function should be split:
    #   - one part creates the raw features (e.g. 'url_tld', 'ip_is_private')
    #   - the preprocessor (ColumnTransformer) then takes these.
    # For now, let's assume data_df is prepared with the columns that ColumnTransformer expects.
    # The `pipeline.predict` will internally call `preprocessor.transform`.

    try:
        predictions = pipeline.predict(data_df)
        probabilities = pipeline.predict_proba(data_df)[:, 1] # Probability of being malicious
        return predictions, probabilities
    except Exception as e:
        print(f"Error during prediction with pipeline: {e}")
        print("Ensure new data has the columns expected by the preprocessor stage of the pipeline.")
        return None, None

# --- Main Orchestration ---
if __name__ == "__main__":
    # 1. Load Data
    raw_df_full = load_data_from_db()

    if raw_df_full.empty:
        print("No data loaded. Exiting.")
    else:
        # 2. Apply Robust Labeling
        labeled_df = apply_robust_labeling_strategy(raw_df_full.copy())

        if 'is_malicious' not in labeled_df.columns or labeled_df['is_malicious'].nunique() < 2:
            print("Labeling resulted in insufficient classes for training. Exiting.")
        else:
            # 3. Feature Engineering & Preprocessing
            # The engineer_features_v2 function now returns the fitted preprocessor
            X_processed, y_target, preprocessor_pipeline, processed_feature_names = engineer_features_v2(labeled_df.copy()) # Pass a copy

            if preprocessor_pipeline is None or (isinstance(X_processed, pd.DataFrame) and X_processed.empty) or X_processed.shape[0] == 0:
                print("Feature engineering or preprocessing failed or produced no samples. Exiting.")
            else:
                # 4. Split Data
                print(f"Splitting data (X_processed shape: {X_processed.shape}, y_target shape: {y_target.shape})...")
                try:
                    # We need the original DataFrame rows corresponding to X_test for example prediction later
                    # So, we split indices from the labeled_df
                    train_indices, test_indices = train_test_split(
                        labeled_df.index, test_size=0.25, random_state=42, stratify=y_target
                    )
                    
                    X_train = X_processed[labeled_df.index.isin(train_indices)]
                    X_test = X_processed[labeled_df.index.isin(test_indices)]
                    y_train = y_target[labeled_df.index.isin(train_indices)]
                    y_test = y_target[labeled_df.index.isin(test_indices)]

                    # Get the original (unprocessed) data for the test set for prediction example
                    df_test_original_features = labeled_df.loc[test_indices].copy()


                    print(f"Train set size: {X_train.shape[0]}, Test set size: {X_test.shape[0]}")
                    if X_train.shape[0] == 0 or X_test.shape[0] == 0 :
                        print("Train or test set is empty after split. Check data and preprocessing. Exiting.")
                        exit()

                    # 5. Train Model
                    # model = train_model(X_train, y_train, model_type='random_forest')
                    model = train_model(X_train, y_train, model_type='logistic_regression')

                    # 6. Create Full Pipeline (Preprocessor + Model)
                    full_pipeline = Pipeline([
                        ('preprocessor', preprocessor_pipeline),
                        ('classifier', model)
                    ])
                    # Note: The preprocessor_pipeline is already fitted.
                    # For a pipeline object, you'd typically fit the whole pipeline:
                    # full_pipeline.fit(X_train_original_features, y_train)
                    # But since preprocessor is already fit, and model is fit on preprocessed data,
                    # this approach of saving preprocessor and model separately or as a custom pipeline is fine.
                    # For simplicity in saving, we'll save the `preprocessor_pipeline` and `model` separately,
                    # or construct a new pipeline with already fitted components for prediction.
                    # Let's save the fitted preprocessor and the model.

                    # 7. Evaluate Model (using the already processed X_test)
                    evaluate_model(model, X_test, y_test, feature_names=processed_feature_names)

                    # 8. Save Preprocessor and Model
                    joblib.dump(preprocessor_pipeline, "preprocessor_v2.joblib")
                    joblib.dump(model, "model_v2.joblib")
                    print(f"Fitted preprocessor saved to preprocessor_v2.joblib")
                    print(f"Trained model saved to model_v2.joblib")

                    # --- Example Prediction using loaded preprocessor and model ---
                    if not df_test_original_features.empty:
                        print("\n--- Example Prediction on a few test samples (using loaded components) ---")
                        
                        # Load them back (as if in a new session)
                        loaded_preprocessor = joblib.load("preprocessor_v2.joblib")
                        loaded_model = joblib.load("model_v2.joblib")

                        sample_new_data_df = df_test_original_features.head(5).copy()
                        
                        # Important: The `sample_new_data_df` must have the columns that the `loaded_preprocessor`
                        # was originally fitted on (i.e., the output of the initial feature creation steps
                        # like adding 'url_tld', 'ip_is_private', etc., BEFORE one-hot encoding/scaling).
                        
                        # The `engineer_features_v2` function created these columns on `labeled_df`.
                        # So, `df_test_original_features` (which is a slice of `labeled_df`) already has them.

                        try:
                            # Transform using the loaded preprocessor
                            sample_data_processed = loaded_preprocessor.transform(sample_new_data_df)
                            
                            # Predict using the loaded model
                            predictions = loaded_model.predict(sample_data_processed)
                            probabilities = loaded_model.predict_proba(sample_data_processed)[:, 1]
                            
                            print("Sample Original Data for Prediction (first 5 from test set):")
                            print(sample_new_data_df[['ioc_value', 'ioc_type', 'source_provider', 'tags_list', 'is_malicious']].head()) # Show true label too
                            print("\nPredictions (1=Malicious, 0=Benign):", predictions)
                            print("Probabilities (of being Malicious):", probabilities)

                        except Exception as e_pred_ex:
                            print(f"Error during example prediction: {e_pred_ex}")
                            print("Ensure the sample data columns match what the preprocessor expects.")
                    else:
                        print("\nNo samples in df_test_original_features for example prediction.")

                except ValueError as e_split:
                    print(f"Error during data splitting or subsequent model steps: {e_split}")
                except Exception as e_main:
                    print(f"An unexpected error occurred in the main ML workflow: {e_main}")
