#!/usr/bin/env python
# coding: utf-8

# # AKAMAI Technologies Inc Report by Sodiq Adebiyi

# ## Data importation and manipulation

# **NOTE: To execute program, set 'mypath' to directory of zip file.**<br>
# **Please rename zip file to Archive.zip and put in a new folder to run script**<br>
# **Import Libraries and install dependencies**

# Please note that this works end to end as in a pipeline and the program will fail to run if the Zip forlder is not named 'Archive'. For easy execution, copy the archive zip file to an empty folder, set mypath to the directory of that folder as prompted in frame 2.

# In[1]:


import time
import pandas as pd
import os
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import scipy

from os import listdir
from os.path import isfile, join

try:
    from zipfile import ZipFile
except:
    get_ipython().system('pip install zipfile')


# In[2]:


mypath = input('Enter directory containing Arcive.zip----> ') #format----------> 'C:/Users/olola/Downloads/Akamai Files


# In[3]:


start_time = time.time()

               Function         |        Usage
--------------------------------|-------------------------------------------------------------------
zipExtractor()                  |Extract the files from the zip archive
parseDict()                     |Build a dictionary with index keys and all the files in the zip archive as values
dfMgmt()                        |Build a unified pandas dataframe of all the files in the dictionary
dataManipulationDriver()        |Transforms the data as required for the report
extractEngInfo()                |Extract Engine specific data from the scan column
createBarPlot()                 |Plot a bar chart to identify the Engine with the most detections
createHeatMap()                 |Create a heat map to show similarity between different Engines at a glance
createCDF()                     |Create the Cummulative frequency curve for the data
urlClass()                      |Identify the reason the url is tagged as malicious
# In[4]:


def zipExtractor():                   
    with ZipFile(mypath+'/Archive.zip', 'r') as zipObj:
        zipObj.extractall(mypath+'/Archive')


# <em>Import all the JSON files into the 'dictOfFiles' dictionary to begin parsing</em>

# In[5]:


def parseDict(mypath):
    files = [f for f in os.listdir(mypath+'/Archive/') if os.path.isfile(os.path.join(mypath+'/Archive/',f))]
    filepaths = [mypath+'/Archive/'+ f for f in files]
    dictOfFiles = {}
    for i in range(len(filepaths)):
        dictOfFiles[i] = pd.read_json(filepaths[i], lines=True)
    return dictOfFiles


# <em>Concatenate all the files into a single dataframe</em>

# In[6]:


def dfMgmt():
    newDF = pd.concat([dictOfFiles[i] for i in range(len(dictOfFiles))], ignore_index = True)
    newDF.head(10)
    return newDF


# <em>Manipulate dataframe to fit requirements</em>

# In[7]:


def dataManipulationDriver(newDF):
    expOutput = pd.DataFrame(columns = ['url', 'detectedURL',], index = [f for f in range(len(newDF))])
    temp=[]
    for i in range(len(newDF)):
        temp.append(str(newDF['url'].iloc[i]).split('/')[2])
    for label, content in newDF.iteritems():
        if label in ['url', 'total', 'scan_date']:
            expOutput[label] = content
        else:
            pass
    expOutput.rename(columns = {'total': 'totalScannedEngines'}, inplace = True)
    expOutput['FDQN'] = pd.DataFrame(temp)
    init = []
    init2 = []
    for index, content in newDF.iterrows():
        eng = []
        for x in content[-1].keys():
            if content[-1][x]['detected']==True:
                eng.append(x)
        init.append(eng)
        init2.append(len(eng))
    expOutput['detectedURL'] = init
    expOutput['numberOfDetectionEngines'] = init2
    return expOutput


# <em>Extract information about each engine</em>

# In[8]:


def extractEngInfo(expOutput):
    temp = []
    for i in range(len(expOutput)):
        for j in range(len(expOutput['detectedURL'].iloc[i])):
            temp.append(expOutput['detectedURL'].iloc[i][j])
    engCount = {}
    for i in set(temp):
        engCount[i] = temp.count(i)
    del(temp)
    engCountDF = pd.DataFrame.from_dict(engCount, orient = 'index')
    engCountDF.reset_index(level=0, inplace=True)
    engCountDF = engCountDF.rename(columns = {'index': 'Engines', 0: 'Detections'})
    engCountDF = engCountDF.sort_values(by = 'Detections', ascending = False)
    return engCountDF


# ## Data Visualization

# <em>Create a Bar Chart for the top 10 engines</em>

# In[9]:


def createBarPlot(simDF):
    clrs = ['grey' if (x < max(simDF['Detections'])) else 'red' for x in simDF['Detections'].to_list() ]
    sns.barplot(x='Engines', y = 'Detections', data = simDF, palette = clrs)
    plt.xticks(rotation=90)
    plt.show()


# <em>Create heatmap to visualize similarity</em>

# In[10]:


def createHeatMap(simDF):#simDF.to_excel('C:/Users/olola/Downloads/Akamai Files/similarity.xlsx')
    for i in simDF['Engines'].tolist():
        simDF[i] = 0
    lx = simDF.columns.tolist()
    lx.remove('Engines')
    lx.remove('Detections')
    #lx is a list of all the engines
    for i in lx:
        for j in range(len(simDF)):
            if simDF['Detections'].iloc[j] < simDF[simDF['Engines']==i]['Detections'].tolist()[0]:
                simDF[i].iloc[j] = (simDF['Detections'].iloc[j] / simDF[simDF['Engines']==i]['Detections'].tolist()[0]) * 100
            elif simDF[simDF['Engines']==i]['Detections'].tolist()[0] < simDF['Detections'].iloc[j]:
                simDF[i].iloc[j] = (simDF[simDF['Engines']==i]['Detections'].tolist()[0] / simDF['Detections'].iloc[j]) * 100
            else:
                simDF[i].iloc[j] = 100

    try:
        simDF.to_csv(path_or_buf = mypath+'/ExtractedFiles/similarity.csv')
    except:
        pass
    temp = simDF.copy(deep = False)
    temp = temp.drop(columns = ['Detections'])
    temp.set_index('Engines', inplace = True)
    temp
    sns.heatmap(data = temp)


# <em>Create Cumulative Distribution Frequency curve</em>

# In[11]:


def createCDF(engCountDF):
    csum = engCountDF['Detections'].sum()
    for i in range(len(engCountDF)):
        engCountDF['PercentageOfDetection'] = (engCountDF['Detections']/csum) *100
        engCountDF['CumSumPercentages'] = engCountDF['PercentageOfDetection'].cumsum(axis=0)
    engCountDF = engCountDF.sort_values(by = 'CumSumPercentages', ascending = True)
    try:
        engCountDF.to_csv(path_or_buf = mypath+'/ExtractedFiles/cdfData.csv')
    except:
        pass
    #engCountDF
    engCountDF = engCountDF.sort_values(by = 'PercentageOfDetection', ascending = True)
    norm_cdf = scipy.stats.norm.cdf(engCountDF['PercentageOfDetection']) # calculate the cdf - also discrete

    # plot the cdf
    sns.set(rc={'figure.figsize':(13.7,12.27)})
    sns.lineplot(x=engCountDF['Engines'], y=norm_cdf)
    plt.xticks(rotation=90)
    plt.show()


# ## Other Information Gathering 

# <em>Print dataframe showing url and sophos label</em>

# In[12]:


def urlClass():
    output2 = newDF.sort_values(by = 'positives', ascending = False,)
    output2 = output2.head(10)
    output2 = output2.reset_index()
    df = pd.DataFrame(np.zeros((len(output2), 2)), columns = ['url', 'category'])

    for index, value in output2.iterrows():
        df['url'].iloc[index] = value[3]
        df['category'].iloc[index]=value[13]['sophos category']
    return df


# ## Execute Program

# In[13]:


zipExtractor()
dictOfFiles = parseDict(mypath)
newDF = dfMgmt()
try:
    newDF.to_csv(path_or_buf = mypath+'/ExtractedFiles/Combined_Dataset.csv')
except:
    pass


# In[14]:


expOutput = dataManipulationDriver(newDF)


# In[15]:


try:
    expOutput.to_csv(path_or_buf = mypath+'/ExtractedFiles/transformedDS.csv')
except:
    pass
expOutput.sort_values(by='totalScannedEngines', ascending = False).head(10)


# In[16]:


engCountDF = extractEngInfo(expOutput)
simDF = engCountDF.head(10)
simDF


# In[17]:


createBarPlot(simDF)


# In[18]:


createHeatMap(simDF)


# In[19]:


createCDF(engCountDF)


# In[20]:


df = urlClass()
df


# ### Execution Time

# In[21]:


print("Execution time-----> %s seconds ---" % (time.time() - start_time))


# In[ ]:




