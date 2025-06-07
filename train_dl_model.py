import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler

# اقرأ البيانات
df = pd.read_csv('dataset.csv')

# نضف الأعمدة: شيل النقط من IPs وخلافه
df.iloc[:, 2] = df.iloc[:, 2].str.replace('.', '', regex=False)
df.iloc[:, 3] = df.iloc[:, 3].str.replace('.', '', regex=False)
df.iloc[:, 5] = df.iloc[:, 5].str.replace('.', '', regex=False)

# افصل المدخلات عن المخرجات (X و y)
X = df.iloc[:, :-1].values
X = X.astype('float64')
y = df.iloc[:, -1].values

# تطبيع البيانات
scaler = StandardScaler()
X = scaler.fit_transform(X)

# قسّم البيانات لتدريب واختبار
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=0)

# بنى موديل بسيط
model = Sequential()
model.add(Dense(64, input_dim=X.shape[1], activation='relu'))
model.add(Dense(32, activation='relu'))
model.add(Dense(1, activation='sigmoid'))

# كمبّله
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# درّبه
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test))

# احفظه
model.save('model.h5')

# احفظ السكيلر كمان علشان تستخدمه في التنبؤ
import joblib
joblib.dump(scaler, 'scaler.pkl')

print("✅ Model trained and saved as model.h5 and scaler.pkl")

