import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# =========================================================
# AWS CONFIGURATION
# =========================================================
# Replace these values with your own AWS credentials IF needed.
# HOWEVER — for security, it is strongly recommended to use:
#   1. aws configure
#   2. environment variables
#   3. IAM roles (best for production / Lambda)
#
# NEVER commit real AWS keys to GitHub.
# =========================================================

AWS_ACCESS_KEY_ID = "ENTER_YOUR_ACCESS_KEY_HERE"
AWS_SECRET_ACCESS_KEY = "ENTER_YOUR_SECRET_ACCESS_KEY_HERE"
AWS_REGION = "us-east-1"


def create_rekognition_client():
    """
    Creates an AWS Rekognition client.

    If placeholder credentials are still present,
    boto3 will fall back to the default credential chain:
    - aws configure
    - environment variables
    - IAM roles

    Returns:
        boto3 Rekognition client
    """

    # If user did nit replace placeholders → use default AWS setup
    if (
        AWS_ACCESS_KEY_ID == "ENTER_YOUR_ACCESS_KEY_HERE"
        or AWS_SECRET_ACCESS_KEY == "ENTER_YOUR_SECRET_ACCESS_KEY_HERE"
    ):
        return boto3.client("rekognition", region_name=AWS_REGION)

    # If user did provide credentials → use them directly
    return boto3.client(
        "rekognition",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )


# Create the Rekognition client once so we reuse it
rekognition = create_rekognition_client()


def check_image_for_threats(bucket, photo):
    """
    Analyzes an image stored in an S3 bucket and determines
    whether it contains potentially dangerous or unsafe content.

    Parameters:
        bucket (str): Name of the S3 bucket
        photo (str): File name of the image in the bucket

    Returns:
        dict: Result containing:
            - ThreatDetected (True/False)
            - ThreatDetails (if threats found)
            - Message (if safe)
            - Error (if something fails)
    """

    try:
      
        # Check for unsafe / explicit content
        # This uses AWS Rekognition moderation API to detect:
        # - violence
        # - explicit content
        # - unsafe imagery
      
        moderation_response = rekognition.detect_moderation_labels(
            Image={"S3Object": {"Bucket": bucket, "Name": photo}}
        )

      
        # Detect general objects in the image
      
        # This returns objects like:
        # - "Gun"
        # - "Person"
        # - "Car"
        # - "Fire"
        labels_response = rekognition.detect_labels(
            Image={"S3Object": {"Bucket": bucket, "Name": photo}},
            MaxLabels=50,          # Max number of labels returned
            MinConfidence=50       # Ignore low-confidence detections
        )

        # This list will store any detected threats
        threat_details = []

        # Process moderation results
      
        for item in moderation_response.get("ModerationLabels", []):
            # Example: "Violence", "Explicit Nudity", etc.
            name = item["Name"]
            confidence = item["Confidence"]

            threat_details.append(
                f"Moderation: {name} ({confidence:.1f}%)"
            )

        
        # Define dangerous object keywords
        # These are objects we personally classify as threats
        danger_keywords = {
            "Gun", "Weapon", "Knife", "Fire", "Explosion",
            "Smoke", "Blood", "Accident", "Rifle", "Pistol"
        }

  
        # Check detected objects against danger list
        for label in labels_response.get("Labels", []):
            label_name = label["Name"]
            confidence = label["Confidence"]

            # If the detected object is considered dangerous
            if label_name in danger_keywords:
                threat_details.append(
                    f"Object: {label_name} ({confidence:.1f}%)"
                )

        # Return final result
        if threat_details:
            # If ANY threats were found
            return {
                "ThreatDetected": True,
                "ThreatDetails": threat_details
            }

        # If nothing dangerous was found
        return {
            "ThreatDetected": False,
            "Message": "No threats found."
        }

    
    # ERROR HANDLING

    # No AWS credentials found
    except NoCredentialsError:
        return {"Error": "AWS credentials not found."}

    # Partial/malformed credentials
    except PartialCredentialsError:
        return {"Error": "Incomplete AWS credentials."}

    # AWS service errors (permissions, invalid bucket, etc.)
    except ClientError as e:
        return {"Error": e.response["Error"]["Message"]}

    # Catch any unexpected errors
    except Exception as e:
        return {"Error": str(e)}


def run():
    """
    Main function to run the threat detection on multiple images.
    """

    # EDIT THIS: Your S3 bucket name
    # =====================================================
    bucket = "ENTER_YOUR_BUCKET_NAME"

    # EDIT THIS: Add your image file names here
    # =====================================================
    photos = [
        "ENTER_IMAGE_FILE_NAME_1",
        "ENTER_IMAGE_FILE_NAME_2",
        "ENTER_IMAGE_FILE_NAME_3"
    ]

    # Loop through each image and analyze it
    for photo in photos:
        print(f"\nChecking: {photo}")

        result = check_image_for_threats(bucket, photo)

        # If threats were found
        if result.get("ThreatDetected"):
            print("Threats detected:")
            for t in result["ThreatDetails"]:
                print(f"- {t}")

        # If image is safe
        elif "Message" in result:
            print(result["Message"])

        # If an error occurred
        else:
            print(f"Error: {result.get('Error')}")

        print("-" * 40)

if __name__ == "__main__":
    run()
