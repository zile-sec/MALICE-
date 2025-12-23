import pandas as pd
from pandas import DataFrame
import seaborn as sb
import numpy as np
import matplotlib.pyplot as plt 
import time
from statsmodels.tsa.seasonal import seasonal_decompose 
from statsmodels.tsa.arima.model import ARIMA

## importing data
# load SDN_DDOS_dataset.csv
pdata_frame = pd.read_csv(
    "/home/zile/Documents/Projects/my_projects/ML /DDOS ATTACKS DATASET FOR SOFTWARE DEFINED NETWORK/dataset_new/SDN_DDOS_dataset.csv",
    index_col=0
)
print("Columns:", list(pdata_frame.columns))
pdata_frame.head(n=9)

## data preprocessing

# parse time column to datetimes and epoch floats
pdata_frame['time_dt'] = pd.to_datetime(pdata_frame['time'], format='%m/%d/%Y, %H:%M:%S', errors='coerce')
pdata_frame['time_float'] = pdata_frame['time_dt'].values.astype('int64') / 1e9
pdata_frame['Newtime'] = pdata_frame['time_dt'].dt.strftime('%Y-%m-%d %H:%M:%S')

# feature engineering: time-based features
_time = pdata_frame['time_dt']
pdata_frame['Time_HM'] = _time.dt.strftime('%H:%M')
edited_time = pdata_frame['Time_HM'].tolist()

#connection count per time interval
# aggregate by the Time_HM column to count connections per minute
new_count_df = pdata_frame.groupby('Time_HM').size().sort_index().to_frame(name='count')

# convert the index (HH:MM) to a datetime index (using today's date) so it is a time series index
new_count_df.index = pd.to_datetime(new_count_df.index, format='%H:%M')

# set frequency to minutely and fill missing values
# Resampling to a fixed frequency (minutely) can introduce missing values (NaN)
# for minutes where no data was present. We fill these with 0.
new_count_df = new_count_df.asfreq('min').fillna(0)

# ensure the count column is numeric
new_count_df['count'] = new_count_df['count'].astype(float)

# decompose data 
# pass the numeric series (counts) into seasonal_decompose with explicit period
result = seasonal_decompose(new_count_df['count'], model='additive', period=60)

class DDOSDetector:
    def __init__(self):
        # Initialize history with the training dataset
        self.history = new_count_df['count'].tolist()
        print("Initializing DDOS Detector (training baseline)...")
        # Fit initial model to determine threshold based on training data residuals
        model = ARIMA(self.history, order=(10,1,0))
        fitted_model = model.fit()
        # Set threshold to 3 standard deviations of the residuals
        self.threshold = 3 * np.std(fitted_model.resid)
        print(f"Detector ready. Threshold set to: {self.threshold:.2f}")

    def detect(self, current_count):
        """
        Detects if the current traffic count is anomalous.
        Returns (is_attack, expected_count, deviation)
        """
        # Fit model on current history to forecast next step
        model = ARIMA(self.history, order=(10,1,0))
        fitted_model = model.fit()
        forecast = fitted_model.forecast()[0]
        
        deviation = abs(current_count - forecast)
        is_attack = deviation > self.threshold
        
        # Update history with the new observed count
        self.history.append(current_count)
        
        return is_attack, forecast, deviation

if __name__ == "__main__":
    result.plot()
    plt.show()

    ## fit the model AIRMA 
    model = ARIMA(new_count_df['count'], order=(10,1,0))
    fitted_model = model.fit()
    print(fitted_model.summary())

    ## plot residual errors 
    residuals_train_data = DataFrame(fitted_model.resid)
    residuals_train_data.plot()
    plt.show()

    ## predict future values
    ddos_prediction = list()
    history = new_count_df['count'].tolist()
    for ddos in range(len(new_count_df)):
        model = ARIMA(history, order = (10,1,0))
        fitted_model = model.fit()
        output = fitted_model.forecast()
        pred = output[0]
        ddos_prediction.append(pred)
        # error = mean_squared_error(new_count_df['count'], ddos_prediction)
        # print('DDOS Prediction MSE: %.3f' % error)
        history.append(pred)
