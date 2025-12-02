# Import Libraries
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from sklearn.metrics import classification_report, accuracy_score

# Step 1: Load the Dataset
# Load the dataset created by prepare_dataset.py
data = pd.read_csv('training_dataset.csv')

# Step 2: Preprocess Data
# The prepare_dataset.py script has already handled categorical encoding.
# We just need to separate features (X) from the target label (y).
# Separate features and target variable
X = data.drop('is_attack', axis=1)
y = data['is_attack']

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Standardize the features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Step 3: Build the Neural Network Model
model = Sequential()
model.add(Dense(64, input_shape=(X_train.shape[1],), activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(32, activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(1, activation='sigmoid'))  # Sigmoid for binary, softmax for multi-class

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Step 4: Train the Model
model.fit(X_train, y_train, epochs=10, batch_size=64, validation_split=0.2)

# Step 5: Evaluate the Model
y_pred = model.predict(X_test)
y_pred = (y_pred > 0.5).astype(int)  # Threshold for binary classification

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:", classification_report(y_test, y_pred))
