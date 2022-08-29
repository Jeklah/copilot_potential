# An Instagram password scraper using Selenium

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
import time
import os
import sys
import argparse


# The following function will create a new instance of Firefox and
# return the driver object
def start_browser():
    options = Options()
    options.headless = True
    driver = webdriver.Firefox(options=options)
    return driver


# The following function will log into Instagram using the provided
# username and password
def login(driver, username, password):
    driver.get("https://www.instagram.com/accounts/login/")
    # Wait until the login page is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='username']"))
    )
    # Find the username and password fields
    username_field = driver.find_element_by_name("username")
    password_field = driver.find_element_by_name("password")
    # Enter the username and password
    username_field.send_keys(username)
    password_field.send_keys(password)
    # Click the login button
    driver.find_element_by_css_selector("button[type='submit']").click()


# The following function will search for the provided username
# and click on it. If the username is not found, the function will
# return False
def search_user(driver, username):
    # Wait until the search bar is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "input[placeholder='Search']"))
    )
    # Find the search bar and enter the username
    search_bar = driver.find_element_by_css_selector("input[placeholder='Search']")
    search_bar.send_keys(username)
    # Wait until the search results are loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "div[class='fuqBx']"))
    )
    # Find the search results
    search_results = driver.find_elements_by_css_selector("div[class='fuqBx']")
    # Loop through the search results
    for result in search_results:
        # If the result is a username
        if result.find_elements_by_css_selector("div[class='d7ByH']"):
            # If the result is the username we are looking for
            if result.find_element_by_css_selector("div[class='d7ByH']").text == username:
                # Click the result
                result.click()
                return True


# The following function will click on the "Edit Profile" button
def edit_profile(driver):
    # Wait until the "Edit Profile" button is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "button[class='sqdOP  L3NKy   y3zKF     ']"))
    )
    # Click the "Edit Profile" button
    driver.find_element_by_css_selector("button[class='sqdOP  L3NKy   y3zKF     ']").click()


# The following function will click the "Change Password" button
def change_password(driver):
    # Wait until the "Change Password" button is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "button[class='sqdOP  L3NKy   y3zKF     ']"))
    )
    # Click the "Change Password" button
    driver.find_element_by_css_selector("button[class='sqdOP  L3NKy   y3zKF     ']").click()


# The following function will get the current password
def get_current_password(driver):
    # Wait until the current password field is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='oldPassword']"))
    )
    # Get the current password
    current_password = driver.find_element_by_css_selector("input[name='oldPassword']").get_attribute("value")
    return current_password


# The following function will get the new password
def get_new_password(driver):
    # Wait until the new password field is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='newPassword']"))
    )
    # Get the new password
    new_password = driver.find_element_by_css_selector("input[name='newPassword']").get_attribute("value")
    return new_password


# The following function will get the new password again
def get_new_password_again(driver):
    # Wait until the new password again field is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='newPasswordAgain']"))
    )
    # Get the new password again
    new_password_again = driver.find_element_by_css_selector("input[name='newPasswordAgain']").get_attribute("value")
    return new_password_again


# The following function will click the "Save" button
def save(driver):
    # Wait until the "Save" button is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "button[class='sqdOP  L3NKy   y3zKF     ']"))
    )
    # Click the "Save" button
    driver.find_element_by_css_selector("button[class='sqdOP  L3NKy   y3zKF     ']").click()


# The following function will click the "Log Out" button
def logout(driver):
    # Wait until the "Log Out" button is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "button[class='sqdOP  L3NKy   y3zKF     ']"))
    )
    # Click the "Log Out" button
    driver.find_element_by_css_selector("button[class='sqdOP  L3NKy   y3zKF     ']").click()
