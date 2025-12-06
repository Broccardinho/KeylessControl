import cv2
import numpy as np
import os

# -------------------------------------------
# Simple perceptual hash (aHash)
# -------------------------------------------
def average_hash(image_path, hash_size=16):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)

    if img is None:
        return None

    # Resize to small square
    img = cv2.resize(img, (hash_size, hash_size))

    # Compute mean
    avg = img.mean()

    # Build hash
    hash_bits = img > avg
    return hash_bits.astype(int).flatten()


# -------------------------------------------
# Hamming distance between two hashes
# -------------------------------------------
def hamming_dist(hash1, hash2):
    if hash1 is None or hash2 is None:
        return 99999
    return np.count_nonzero(hash1 != hash2)


# -------------------------------------------
# Compare uploaded image to each user image
# -------------------------------------------
def compare_to_database(uploaded_img_path, users):
    """
    Simple face match based on pixel similarity.
    If a user has no image, skip them.
    """

    try:
        uploaded_img = cv2.imread(uploaded_img_path)
        if uploaded_img is None:
            return False, None
        uploaded_gray = cv2.cvtColor(uploaded_img, cv2.COLOR_BGR2GRAY)
    except:
        return False, None

    base_dir = "/var/www/FlaskApp/FlaskApp"

    best_match_user = None
    lowest_diff = 999999999

    for user in users:
        img_rel = user.get("image")

        #  Skip rows with no image saved
        if not img_rel:
            continue

        # Normalize stored path
        img_path = os.path.join(base_dir, img_rel.lstrip("/"))

        # Load DB image
        db_img = cv2.imread(img_path)
        if db_img is None:
            continue

        db_gray = cv2.cvtColor(db_img, cv2.COLOR_BGR2GRAY)

        # Resize to same size
        try:
            db_gray = cv2.resize(db_gray, (uploaded_gray.shape[1], uploaded_gray.shape[0]))
        except:
            continue

        # Compute naive pixel difference
        diff = cv2.absdiff(uploaded_gray, db_gray).sum()

        if diff < lowest_diff:
            lowest_diff = diff
            best_match_user = user

    #  Adjust threshold to your liking
    if lowest_diff < 5000000:
        return True, best_match_user

    return False, None