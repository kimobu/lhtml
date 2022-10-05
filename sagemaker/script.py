
import argparse
import joblib
import os
import numpy as np
import pandas as pd
import json
from sagemaker_containers.beta.framework import worker


def parse_segment(load_command: object):
    segment = {}
    lname = load_command["name"]
    segment["name"] = lname
    segment[f"segment_{lname}_vmsize"] = load_command["vmsize"]
    segment[f"segment_{lname}_size"] = load_command["size"]
    segment[f"segment_{lname}_initprot"] = load_command["initprot"]
    segment[f"segment_{lname}_maxprot"] = load_command["maxprot"]
    segment[f"segment_{lname}_nsects"] = load_command["nsects"]
    segment[f"segment_{lname}_entropy"] = load_command["entropy"]
    for sect in load_command["sects"]:
        sectname = sect["name"]
        segment[f"segment_{lname}_{sectname}"] = sect
    return segment


def parse_loaddylib(load_command: object, mach: object):
    dylib = {}
    dname = load_command["name"]
    dylib["name"] = dname
    if "imports" in mach["macho"].keys():
        impcount = 0
        for imp in mach["macho"]["imports"]:
            if imp[1] == dname:
                impcount += 1
        dylib[f"dylib_{dname}_imports"] =  impcount
    return dylib


def parse_json(data: object):
    mach = {}
    mach["name"] = data["name"]
    mach["size"] = data["size"]
    mach["entropy"] = data["entropy"]
    mach["nlcs"] = data["macho"]["nlcs"]
    mach["slcs"] = data["macho"]["slcs"]
    for flag in data["macho"]["flags"]:
        fname = f"flag_{flag}"
        mach[fname] = 1
    num_segments = 0
    num_imports = 0
    for load_command in data["macho"]["lcs"]:
        lc_type = load_command["cmd"]
        if lc_type == "SEGMENT" or lc_type == "SEGMENT_64":
            num_segments += 1
            segment = parse_segment(load_command)
            sname = segment["name"]
            mach[f"{sname}"] = 1
            for k,v in segment.items():
                mach[f"{k}"] = v
        if lc_type == "LOAD_DYLIB":
            num_imports += 1
            dylib = parse_loaddylib(load_command, data)
            dname = dylib["name"]
            mach[f"{dname}"] = 1
            for k,v in dylib.items():
                mach[f"{k}"] = v
    mach["num_segments"] = num_segments
    mach["num_imports"] = num_imports
    return mach

def preprocess(df):
    with open('/opt/ml/model/features.json', 'r') as f:
        features = json.loads(f.read())
    newdf = pd.DataFrame(columns=features)
    for col in df.columns:
        if "imports" in col:
            df[col] = df[col].astype('object')

    count=0
    for col in newdf.columns:
        if col in df.columns:
            if isinstance(df.at[count, col], dict):
                # Instead of storing the dict, store the presence-of
                newdf.at[count, col] = 1
            else:
                newdf.at[count, col] = df.at[count,col]
        else:
            if "imports" in col:
                # If the column was not present, call it -1 as an arbitrary "did not exist" value
                newdf.at[count, col] = -1
    newdf = newdf.replace({pd.NA: np.nan})
    return newdf

                
def input_fn(input_data, content_type):
    """Parse input data payload
    """
    print("in input")
    if content_type == 'application/json':
        json_data = json.loads(input_data)
        data = parse_json(json_data)
        df = pd.read_json(json.dumps([data]), orient="records")
        ndf = preprocess(df)
        return ndf
    else:
        raise ValueError("{} not supported by script!".format(content_type))


def output_fn(output_data, accept):
    """Format prediction output

    The default accept/content-type between containers for serial inference is JSON.
    We also want to set the ContentType or mimetype as the same value as accept so the next
    container can read the response payload correctly.
    """
    print(f"in output, will return {output_data}")
    if accept == "application/json":
        return worker.Response(json.dumps(output_data), mimetype=accept)
    elif accept == 'text/csv':
        return worker.Response(output_data.to_csv(), mimetype=accept)
    else:
        raise RuntimeException("{} accept type is not supported by this script.".format(accept))


def predict_fn(input_data, model):
    """Predict values based on input data
    """
    print("Predicting values")
    predictions = model.predict(input_data[model[0].feature_names_in_])
    if predictions[0] == 1:
        response = {"result": "malware"}
    else:
        response = {"result": "benign"}
    return response    


def model_fn(model_dir):
    """Deserialize fitted model
    """
    print("Loading model")
    preprocessor = joblib.load(os.path.join(model_dir, "model1.joblib"))
    return preprocessor


if __name__ == "__main__":
    print('in main')
