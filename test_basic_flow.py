"""
Test script to run the basic flow of twscrape.
This script demonstrates:
1. Creating an API instance
2. Adding an account with cookies
3. Making basic API calls (user lookup, tweet details, search)
"""

import asyncio
import os

from twscrape import API, gather
from twscrape.logger import set_log_level

# Target user to fetch tweets from
TARGET_USER = "iamrishavanand"


async def main():
    # Enable debug logging for detailed output
    set_log_level("DEBUG")

    # Create API instance with a test database
    db_path = "test_accounts.db"
    api = API(db_path)

    print("=" * 50)
    print("TWSCRAPE BASIC FLOW TEST")
    print("=" * 50)

    # Check for account credentials in environment variables
    username = os.getenv("TW_USERNAME")
    password = os.getenv("TW_PASSWORD")
    email = os.getenv("TW_EMAIL")
    email_password = os.getenv("TW_EMAIL_PASSWORD")
    cookies = os.getenv("TW_COOKIES")

    # Check if we already have active accounts
    accounts = await api.pool.accounts_info()
    active_accounts = [a for a in accounts if a.get("active")]

    if active_accounts:
        print(f"\n[1] Using existing active account: {active_accounts[0]['username']}")
    elif cookies:
        print("\n[1] Adding account with cookies...")
        await api.pool.add_account(
            username or "test_user",
            password or "test_pass",
            email or "test@example.com",
            email_password or "mail_pass",
            cookies=cookies
        )
        print("Account added with cookies!")
    elif username and password and email:
        print("\n[1] Adding account with credentials...")
        await api.pool.add_account(username, password, email, email_password or "")
        print("Attempting login...")
        await api.pool.login_all()
        print("Login complete!")
    else:
        print("\n[1] No credentials provided and no active accounts.")
        print("Set environment variables to test with real account:")
        print("  TW_USERNAME, TW_PASSWORD, TW_EMAIL, TW_EMAIL_PASSWORD")
        print("  Or TW_COOKIES for cookie-based auth")
        print("\nSkipping API tests (no account available)")
        return

    # Test API calls
    print("\n[2] Testing API calls...")

    # Test 1: Get user by login
    print(f"\n--- Test: user_by_login (@{TARGET_USER}) ---")
    try:
        user = await api.user_by_login(TARGET_USER)
        if user:
            print(f"User: @{user.username}")
            print(f"Name: {user.displayname}")
            print(f"ID: {user.id}")
            print(f"Followers: {user.followersCount}")
            target_user_id = user.id
        else:
            print("User not found")
            return
    except Exception as e:
        print(f"Error: {e}")
        return

    # Test 2: Get user tweets
    print(f"\n--- Test: user_tweets (@{TARGET_USER}) ---")
    try:
        tweets = await gather(api.user_tweets(target_user_id, limit=10))
        print(f"Found {len(tweets)} tweets from @{TARGET_USER}\n")
        for i, tweet in enumerate(tweets, 1):
            content = tweet.rawContent[:80] + "..." if len(tweet.rawContent) > 80 else tweet.rawContent
            print(f"{i}. {content}")
            print(f"   Likes: {tweet.likeCount}, Retweets: {tweet.retweetCount}")
            print()
    except Exception as e:
        print(f"Error: {e}")

    print("\n" + "=" * 50)
    print("BASIC FLOW TEST COMPLETE")
    print("=" * 50)

    # Cleanup test database
    if os.path.exists(db_path):
        print(f"\nNote: Test database created at: {db_path}")
        print("You can delete it manually or keep it for future tests.")


if __name__ == "__main__":
    asyncio.run(main())
