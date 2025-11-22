# simulator/mock_recognizer.py
import os
import random

SAMPLES_DIR = "simulator/samples/"

def load_known_faces():
    """
    Fake database matching:
    adam_1.jpg -> Adam
    adil_1.jpg -> Adil
    unknown.jpg -> unknown user
    """
    known = {}
    for file in os.listdir(SAMPLES_DIR):
        user = file.split("_")[0].capitalize()
        known[file] = user
    return known

def pick_random_sample():
    files = os.listdir(SAMPLES_DIR)
    return random.choice(files)

def mock_recognize():
    known = load_known_faces()
    chosen = pick_random_sample()

    if chosen in known:
        return True, known[chosen]
    return False, None
