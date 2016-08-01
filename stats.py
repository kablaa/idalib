import math

def mean(data): return (float(sum(data)) / float(len(data)))

def variance(data): return float(sum([pow(x-mean(data),2) for x in data])) / float(len(data))

def ZScores(data): return [(x - mean(data))/math.sqrt(variance(data)) for x in data]
