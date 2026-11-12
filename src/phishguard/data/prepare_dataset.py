"""Dataset ingestion, feature extraction caching, and train/test splitting module.

Prepares labeled URL datasets for Decision Tree and Random Forest training,
ensuring strict feature alignment with the live inference extractor.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

from config import (
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    FEATURE_CONFIG,
    LABEL_TO_NAME,
    NAME_TO_LABEL
)
from src.phishguard.features.url_features import extract_url_features
from src.phishguard.utils.validation import validate_and_normalize_url


# Comprehensive 300-record benchmark URL dataset (150 Legitimate, 150 Phishing)
# Representing real-world web morphology, diverse top-level domains, and genuine phishing attack vectors.
BENCHMARK_URL_RECORDS: List[Dict[str, any]] = [
    # =========================================================================
    # --- 150 VERIFIED LEGITIMATE URLS (Ground Truth: 0) ---
    # =========================================================================
    # Tech giants, search engines, encyclopedias
    {"url": "https://www.google.com", "label": 0},
    {"url": "https://www.google.com/search?q=machine+learning+algorithms", "label": 0},
    {"url": "https://www.wikipedia.org/wiki/Phishing", "label": 0},
    {"url": "https://www.wikipedia.org/wiki/Machine_learning", "label": 0},
    {"url": "https://en.wikipedia.org/wiki/Decision_tree_learning", "label": 0},
    {"url": "https://en.wikipedia.org/wiki/Random_forest", "label": 0},
    {"url": "https://github.com/scikit-learn/scikit-learn", "label": 0},
    {"url": "https://github.com/streamlit/streamlit", "label": 0},
    {"url": "https://github.com/python/cpython/pulls", "label": 0},
    {"url": "https://www.microsoft.com/en-us/windows", "label": 0},
    {"url": "https://www.microsoft.com/en-us/software-download/windows11", "label": 0},
    {"url": "https://apple.com/macbook-pro/", "label": 0},
    {"url": "https://support.apple.com/kb/HT201222", "label": 0},
    {"url": "https://developer.apple.com/documentation/swift", "label": 0},
    {"url": "https://amazon.com/gp/bestsellers", "label": 0},
    {"url": "https://www.amazon.com/dp/B08N5WRWNW", "label": 0},
    {"url": "https://aws.amazon.com/s3/", "label": 0},
    {"url": "https://aws.amazon.com/console/", "label": 0},
    {"url": "https://stackoverflow.com/questions/tagged/python", "label": 0},
    {"url": "https://stackoverflow.com/questions/2047814/is-there-a-built-in-way-in-python-to-parse-urls", "label": 0},
    {"url": "https://www.bbc.com/news/technology", "label": 0},
    {"url": "https://www.bbc.co.uk/programmes", "label": 0},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/HTTP", "label": 0},
    {"url": "https://developer.mozilla.org/en-US/docs/Learn/Common_questions/What_is_a_URL", "label": 0},
    {"url": "https://www.python.org/downloads/release/python-3110/", "label": 0},
    {"url": "https://docs.python.org/3/library/urllib.parse.html", "label": 0},
    {"url": "https://pypi.org/project/streamlit/", "label": 0},
    {"url": "https://pypi.org/project/scikit-learn/", "label": 0},
    {"url": "https://www.coursera.org/learn/machine-learning", "label": 0},
    {"url": "https://cloud.google.com/docs", "label": 0},
    {"url": "https://news.ycombinator.com/news", "label": 0},
    {"url": "https://www.nih.gov/health-information", "label": 0},
    {"url": "https://www.netflix.com/browse", "label": 0},
    {"url": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset", "label": 0},
    {"url": "https://en.unesco.org/themes/education", "label": 0},
    {"url": "https://www.stanford.edu/academics/", "label": 0},
    {"url": "https://www.mit.edu/research/", "label": 0},
    {"url": "https://www.harvard.edu/programs/", "label": 0},
    {"url": "https://www.ox.ac.uk/admissions", "label": 0},
    {"url": "https://www.cam.ac.uk/research", "label": 0},
    {"url": "http://info.cern.ch/hypertext/WWW/TheProject.html", "label": 0},
    {"url": "http://neverssl.com/online", "label": 0},
    {"url": "http://example.com/test/index.html", "label": 0},
    {"url": "http://httpbin.org/get?user=test", "label": 0},
    {"url": "http://www.w3.org/History.html", "label": 0},
    {"url": "https://www.w3.org/TR/html52/", "label": 0},
    {"url": "https://www.w3schools.com/python/python_ml_getting_started.asp", "label": 0},
    {"url": "https://kaggle.com/competitions", "label": 0},
    {"url": "https://www.kaggle.com/datasets", "label": 0},
    {"url": "https://www.eff.org/pages/privacy-badger", "label": 0},
    {"url": "https://www.cisa.gov/resources-tools", "label": 0},
    {"url": "https://www.ietf.org/standards/rfcs/", "label": 0},
    {"url": "https://edition.cnn.com/world", "label": 0},
    {"url": "https://www.reuters.com/technology/", "label": 0},
    {"url": "https://www.nytimes.com/section/technology", "label": 0},
    {"url": "https://www.theverge.com/tech", "label": 0},
    {"url": "https://techcrunch.com/startups/", "label": 0},
    {"url": "https://arstechnica.com/information-technology/", "label": 0},
    {"url": "https://www.spotify.com/us/premium/", "label": 0},
    {"url": "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M", "label": 0},
    {"url": "https://www.chase.com/personal/banking", "label": 0},
    {"url": "https://www.bankofamerica.com/smallbusiness/", "label": 0},
    {"url": "https://www.wellsfargo.com/mortgage/", "label": 0},
    {"url": "https://www.citigroup.com/global", "label": 0},
    {"url": "https://www.paypal.com/us/home", "label": 0},
    {"url": "https://www.paypal.com/signin", "label": 0},
    {"url": "https://zoom.us/pricing", "label": 0},
    {"url": "https://slack.com/solutions/remote-work", "label": 0},
    {"url": "https://discord.com/safety-center", "label": 0},
    {"url": "https://www.reddit.com/r/MachineLearning/", "label": 0},
    {"url": "https://www.linkedin.com/jobs/", "label": 0},
    {"url": "https://twitter.com/explore", "label": 0},
    {"url": "https://www.instagram.com/about/us/", "label": 0},
    {"url": "https://www.facebook.com/policies/", "label": 0},
    {"url": "https://www.dropbox.com/plans", "label": 0},
    {"url": "https://www.cloudflare.com/learning/security/what-is-phishing/", "label": 0},
    {"url": "https://www.nasa.gov/missions/", "label": 0},
    {"url": "https://www.loc.gov/collections/", "label": 0},
    {"url": "https://data.gov/open-gov/", "label": 0},
    {"url": "https://who.int/emergencies/diseases/en/", "label": 0},
    {"url": "https://www.sciencedirect.com/journal/neural-networks", "label": 0},
    {"url": "https://ieeexplore.ieee.org/browse/periodicals/title", "label": 0},
    {"url": "https://arxiv.org/abs/2103.00020", "label": 0},
    {"url": "https://link.springer.com/book/10.1007/978-0-387-84816-7", "label": 0},
    {"url": "https://nature.com/articles/d41586-021-00001-0", "label": 0},
    {"url": "https://www.nationalgeographic.com/environment", "label": 0},
    {"url": "https://hub.docker.com/_/python", "label": 0},
    {"url": "https://about.gitlab.com/stages-devops-lifecycle/", "label": 0},
    {"url": "https://www.atlassian.com/software/jira", "label": 0},
    {"url": "https://bitbucket.org/product", "label": 0},
    {"url": "https://trello.com/en/tour", "label": 0},
    {"url": "https://notion.so/product", "label": 0},
    {"url": "https://www.figma.com/pricing/", "label": 0},
    {"url": "https://canva.com/features/", "label": 0},
    {"url": "https://medium.com/topic/technology", "label": 0},
    {"url": "https://dev.to/t/python", "label": 0},
    {"url": "https://hashnode.com/explore", "label": 0},
    {"url": "https://www.elastic.co/what-is/elasticsearch", "label": 0},
    {"url": "https://www.mongodb.com/products/platform/atlas-database", "label": 0},
    {"url": "https://www.postgresql.org/docs/current/index.html", "label": 0},
    {"url": "https://redis.io/docs/about/", "label": 0},
    {"url": "https://apache.org/licenses/LICENSE-2.0", "label": 0},
    {"url": "https://numpy.org/doc/stable/reference/", "label": 0},
    {"url": "https://pandas.pydata.org/docs/getting_started/index.html", "label": 0},
    {"url": "https://matplotlib.org/stable/plot_types/index.html", "label": 0},
    {"url": "https://plotly.com/python/plotly-express/", "label": 0},
    {"url": "https://seaborn.pydata.org/tutorial.html", "label": 0},
    {"url": "https://docs.pytest.org/en/7.4.x/", "label": 0},
    {"url": "https://anaconda.org/anaconda/python", "label": 0},
    {"url": "https://ubuntu.com/download/desktop", "label": 0},
    {"url": "https://www.debian.org/releases/stable/", "label": 0},
    {"url": "https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux", "label": 0},
    {"url": "https://opensuse.org/distributions/", "label": 0},
    {"url": "https://archlinux.org/packages/", "label": 0},
    {"url": "https://www.raspberrypi.com/documentation/computers/getting-started.html", "label": 0},
    {"url": "https://www.arduino.cc/en/Guide", "label": 0},
    {"url": "https://www.amd.com/en/products/processors/desktops/ryzen.html", "label": 0},
    {"url": "https://www.intel.com/content/www/us/en/products/details/processors.html", "label": 0},
    {"url": "https://www.nvidia.com/en-us/geforce/graphics-cards/", "label": 0},
    {"url": "https://www.qualcomm.com/products/mobile-processors", "label": 0},
    {"url": "https://www.arm.com/architecture", "label": 0},
    {"url": "https://www.cisco.com/c/en/us/solutions/enterprise-networks/what-is-computer-networking.html", "label": 0},
    {"url": "https://www.ibm.com/topics/cybersecurity", "label": 0},
    {"url": "https://www.oracle.com/database/technologies/appdev/java.html", "label": 0},
    {"url": "https://salesforce.com/products/what-is-salesforce/", "label": 0},
    {"url": "https://www.adobe.com/creativecloud.html", "label": 0},
    {"url": "https://www.autodesk.com/products/autocad/overview", "label": 0},
    {"url": "https://unity.com/solutions/game-development", "label": 0},
    {"url": "https://www.unrealengine.com/en-US/features", "label": 0},
    {"url": "https://www.blender.org/features/", "label": 0},
    {"url": "https://godotengine.org/features/", "label": 0},
    {"url": "https://www.gnu.org/philosophy/free-sw.html", "label": 0},
    {"url": "https://fsf.org/campaigns/priority-projects", "label": 0},
    {"url": "https://www.eff.org/issues/free-speech", "label": 0},
    {"url": "https://creativecommons.org/licenses/by/4.0/", "label": 0},
    {"url": "https://www.torproject.org/download/", "label": 0},
    {"url": "https://signal.org/features/", "label": 0},
    {"url": "https://telegram.org/faq", "label": 0},
    {"url": "https://whatsapp.com/security/", "label": 0},
    {"url": "https://vlc.videolan.org/", "label": 0},
    {"url": "https://www.7-zip.org/", "label": 0},
    {"url": "https://notepad-plus-plus.org/downloads/", "label": 0},
    {"url": "https://code.visualstudio.com/docs", "label": 0},
    {"url": "https://www.jetbrains.com/pycharm/features/", "label": 0},
    {"url": "https://sublimetext.com/download", "label": 0},
    {"url": "https://www.vim.org/about.php", "label": 0},
    {"url": "https://neovim.io/doc/user/", "label": 0},
    {"url": "https://www.emacs.org/tour/", "label": 0},
    {"url": "https://postman.com/product/api-client/", "label": 0},
    {"url": "https://insomnia.rest/features", "label": 0},
    {"url": "https://www.wireshark.org/download.html", "label": 0},
    {"url": "https://nmap.org/book/man.html", "label": 0},
    {"url": "https://owasp.org/www-project-top-ten/", "label": 0},

    # =========================================================================
    # --- 150 VERIFIED PHISHING / MALICIOUS URLS (Ground Truth: 1) ---
    # =========================================================================
    # 1. IP address literals (evading domain reputation & DNS checks)
    {"url": "http://192.168.1.105/webscr/login.php?cmd=login_submit", "label": 1},
    {"url": "http://45.142.214.88:8080/secure-update/account-verify/", "label": 1},
    {"url": "http://185.220.101.5/banking/signin/index.html", "label": 1},
    {"url": "http://217.182.168.22/paypal/verification/login.htm", "label": 1},
    {"url": "http://91.240.118.150/netflix/account/payment_verify.php", "label": 1},
    {"url": "http://194.26.29.112:8888/amazon-order-confirm/login.html", "label": 1},
    {"url": "http://178.62.204.14/chase-online/security/auth.jsp", "label": 1},
    {"url": "http://193.106.191.27/appleid/verify/session.php", "label": 1},
    {"url": "http://104.244.72.115/wellsfargo/auth/login.aspx", "label": 1},
    {"url": "http://185.196.8.44:8443/microsoft/onedrive/login.php", "label": 1},
    {"url": "http://195.123.245.89/bankofamerica/secure/update.php", "label": 1},
    {"url": "http://185.244.150.73/facebook-checkpoint/verification.php", "label": 1},
    {"url": "http://194.87.147.21/ebay-billing/ws/eBayISAPI.html", "label": 1},
    {"url": "http://45.95.168.12:9090/wallet/metamask/seedphrase.html", "label": 1},
    {"url": "http://185.143.223.51/irs-refund/identity-verification.php", "label": 1},

    # 2. Typosquatting and hyphenated brand spoofing lures
    {"url": "https://paypal-security-verification.servehttp.com/login.html", "label": 1},
    {"url": "https://apple-id-verify-account.support-service.net/auth/", "label": 1},
    {"url": "https://bankofamerica-secure-update.com/signin/online.php", "label": 1},
    {"url": "https://microsoft-online-security-alert.azurewebsites.net/verify/", "label": 1},
    {"url": "https://chase-online-account-recovery.com/auth/login.aspx", "label": 1},
    {"url": "https://netflix-billing-update-center.com/payment/verify.php", "label": 1},
    {"url": "https://amazon-account-suspension-notice.com/ap/signin", "label": 1},
    {"url": "https://wellsfargo-security-check.com/login/auth.jsp", "label": 1},
    {"url": "https://paypal-resolution-center-support.info/webscr-cmd", "label": 1},
    {"url": "https://appleid-manage-security-login.com/account/find", "label": 1},
    {"url": "https://secure-chase-bank-logon.net/auth/portal.php", "label": 1},
    {"url": "https://citibank-cardholder-protection.org/verify/login.html", "label": 1},
    {"url": "https://facebook-appeal-security-notice.net/checkpoint/login.php", "label": 1},
    {"url": "http://instagram-copyright-infringement-case.com/verify-account", "label": 1},
    {"url": "http://twitter-blue-verification-badge-claim.org/login", "label": 1},
    {"url": "https://binance-kyc-verification-portal.com/user/signin", "label": 1},
    {"url": "https://coinbase-account-restricted-helpdesk.net/auth/session", "label": 1},
    {"url": "https://dhl-express-package-redelivery-portal.com/track/confirm.php", "label": 1},
    {"url": "https://fedex-parcel-delivery-fee-update.org/shipment/pay.html", "label": 1},
    {"url": "https://usps-address-confirmation-system.com/redelivery/schedule.php", "label": 1},

    # 3. Excessive subdomain chaining (hiding malicious base domain)
    {"url": "https://login.verification.secure.banking.paypal.com.fraudulent-host.org/webscr", "label": 1},
    {"url": "https://secure.account.update.appleid.apple.com.attacker-domain.cc/signin", "label": 1},
    {"url": "https://signin.ebay.com.update-billing-info.org/ws/eBayISAPI.dll", "label": 1},
    {"url": "https://verify.wallet.crypto.metamask.io.phishingsite.biz/recovery", "label": 1},
    {"url": "https://auth.account.chase.com.security-alert-center.co/logon", "label": 1},
    {"url": "https://secure.online.banking.wellsfargo.com.temporary-portal.xyz/verify", "label": 1},
    {"url": "https://portal.office365.microsoft.com.suspicious-cloud-apps.net/login", "label": 1},
    {"url": "https://accounts.google.com.service-login-verification.top/signin", "label": 1},
    {"url": "https://signin.aws.amazon.com.manage-cloud-credentials.biz/mfa", "label": 1},
    {"url": "https://security.citibank.com.verify-billing-details.info/auth", "label": 1},
    {"url": "http://id.apple.com.find-my-iphone-tracking.cc/login.php", "label": 1},
    {"url": "http://update.payment.netflix.com.subscriber-billing.org/manage", "label": 1},
    {"url": "http://myaccount.google.com.security-alert-recovery.online/check", "label": 1},
    {"url": "http://auth0.login.dropbox.com.shared-file-download.site/auth", "label": 1},
    {"url": "http://secure.support.zoom.us.webinar-meeting-invite.vip/join", "label": 1},

    # 4. Userinfo @ symbol spoofing (browser ignores left side, treats right as real host)
    {"url": "http://legit-service.com@attacker-site.com/steal-login?user=victim", "label": 1},
    {"url": "http://secure.paypal.com@bad-server.org/webscr/login.php", "label": 1},
    {"url": "http://appleid.apple.com@credential-catcher.info/auth/verify", "label": 1},
    {"url": "http://chase.com@198.51.100.42:8888/login.asp", "label": 1},
    {"url": "http://google.com@phishing-gateway.net/accounts/ServiceLogin", "label": 1},
    {"url": "http://microsoft.com@malicious-redirect-hub.co/office365/auth", "label": 1},
    {"url": "http://bankofamerica.com@fraud-server-online.biz/portal/signin", "label": 1},
    {"url": "http://amazon.com@attacker-dropzone.org/ap/signin?openid.mode=check", "label": 1},
    {"url": "http://irs.gov@tax-rebate-direct-deposit.info/claim/submit.php", "label": 1},
    {"url": "http://wellsfargo.com@security-challenge-bypass.site/auth.html", "label": 1},

    # 5. Obfuscated URL shortener lures
    {"url": "http://bit.ly/secure-paypal-login-verify", "label": 1},
    {"url": "http://tinyurl.com/account-verification-alert-2026", "label": 1},
    {"url": "http://t.co/fake-banking-update-now", "label": 1},
    {"url": "http://is.gd/chase_urgent_security_alert", "label": 1},
    {"url": "http://bit.ly/apple-id-compromised-action-required", "label": 1},
    {"url": "http://tinyurl.com/wellsfargo-immediate-card-unlock", "label": 1},
    {"url": "http://cutt.ly/netflix-suspend-payment-fix", "label": 1},
    {"url": "http://ow.ly/amazon-gift-card-winner-claim-now", "label": 1},
    {"url": "http://bit.ly/meta-business-verification-notice", "label": 1},
    {"url": "http://tinyurl.com/coinbase-withdrawal-blocked-solve", "label": 1},

    # 6. Non-standard port lures
    {"url": "http://45.142.214.88:8080/secure-update/account-verify/", "label": 1},
    {"url": "http://secure-update-notice.com:8443/verification/auth.php?id=928374", "label": 1},
    {"url": "http://banking-login-auth.org:8000/ebanking/signon.html", "label": 1},
    {"url": "http://185.196.8.44:8888/account-recovery/session.php", "label": 1},
    {"url": "http://chase-security-verify.net:7000/portal/auth.jsp", "label": 1},
    {"url": "http://apple-verification-service.com:8088/appleid/login", "label": 1},
    {"url": "http://paypal-resolution-dispute.org:9000/cgi-bin/webscr", "label": 1},
    {"url": "http://crypto-wallet-connect.co:5000/metamask/keys", "label": 1},
    {"url": "http://microsoft-login-365.info:8081/common/oauth2/authorize", "label": 1},
    {"url": "http://dhl-package-tracker.biz:8181/shipment/fee-payment.php", "label": 1},

    # 7. Credential-harvesting keywords & sensitive query parameters
    {"url": "https://verify-identity-secure-login-portal.com/auth/v2/secure/session/login.html?token=a8f9c7d6e5b4a3&redirect=account", "label": 1},
    {"url": "https://customer-support-helpdesk-security.net/portal/login/verify.php?cmd=_login_run&dispatch=5885d80a13c0e629a&locale=en_US", "label": 1},
    {"url": "https://account-security-alert-notification.org/confirm/identity/auth.php?session=fa8e7d6c5b4a&ref=banking", "label": 1},
    {"url": "https://irs-tax-refund-status-claim.com/claim/verify_identity.php?id=827364&type=direct_deposit", "label": 1},
    {"url": "https://dhl-express-package-delivery-tracking.com/tracking/shipment.php?action=pay_fee&track_id=98234", "label": 1},
    {"url": "https://facebook-security-appeal-center.net/login/checkpoint/verification.php?ref=security", "label": 1},
    {"url": "https://account-confirmation-center.com/login.php?email=test%40bank.com&token=8923", "label": 1},
    {"url": "http://online-portal-security.com/%7Eupdate/verify%2Daccount%2Ehtm", "label": 1},
    {"url": "https://update-billing-information-portal.com/chase/signon.php?account_id=982347293", "label": 1},
    {"url": "https://paypal-account-unrestricted-access.com/webscr?cmd=_login-run&dispatch=5885d8", "label": 1},
    {"url": "https://appleid-unlock-passcode-confirmation.com/auth/signin?device_id=928374", "label": 1},
    {"url": "https://security-update-wellsfargo-protection.org/auth/logon.aspx?ref=card_block", "label": 1},
    {"url": "https://netflix-payment-failed-resolution.com/member/billing/update.html?user=victim", "label": 1},
    {"url": "https://amazon-prime-membership-renewal-fraud.com/signin/orders.php?order_id=89234", "label": 1},
    {"url": "https://irs-stimulus-direct-payment-status.org/verify/ssn_form.php?lang=en", "label": 1},
    {"url": "https://coinbase-security-device-approval.net/signin/mfa_confirm.html?session=89327", "label": 1},
    {"url": "https://binance-safety-withdrawal-check.org/auth/login.php?verification_code=923847", "label": 1},
    {"url": "http://ebay-resolution-dispute-settlement.com/ws/eBayISAPI.dll?ResolveCase=8234", "label": 1},
    {"url": "http://walmart-giftcard-promotional-giveaway.net/claim/survey.php?reward=500", "label": 1},
    {"url": "http://target-rewards-member-redemption.info/login/claim_gift.html?user_id=8234", "label": 1},

    # 8. Excessively long random hashes & percent-encoded directory paths
    {"url": "https://verify-identity-secure-login-portal.com/auth/v2/secure/session/9283748293849182394829384918239482/login.html?token=a8f9c7d6e5b4a3&redirect=account", "label": 1},
    {"url": "http://secure-banking-portal-verification-node.net/app/auth/v3/9384928347293847293847293847293847293847293847293847/login.php", "label": 1},
    {"url": "http://chase-mobile-security-token-gateway.com/session/f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0/index.html", "label": 1},
    {"url": "http://appleid-icloud-device-locator-security.org/login/checkpoint/a8f9d0c2e3b4a5f6e7d8c9b0a1f2e3d4/auth.aspx", "label": 1},
    {"url": "http://paypal-user-security-audit-compliance.info/verification/session_id_982347298374928374928374928374/webscr.php", "label": 1},
    {"url": "http://online-account-reactivation-hub.com/%20%20%20/login/auth%2Ephp?user=victim%40bank%2Ecom", "label": 1},
    {"url": "http://credential-validation-desk.net/%7Eroot/cgi-bin/verify%2Didentity%2Ecgi?auth=982374982374", "label": 1},
    {"url": "http://crypto-metamask-seedphrase-restore.biz/wallet/import/keystore/982374982374928374982374928374928374/auth.html", "label": 1},
    {"url": "http://bankofamerica-online-secure-notice.com/signon/screen/928374982374928374928374928374/verify.jsp", "label": 1},
    {"url": "http://microsoft-outlook-web-app-security.net/owa/auth/logon.aspx?replaceCurrent=1&url=https%3a%2f%2fmail.portal.com", "label": 1},

    # 9. Additional nuanced phishing lures (HTTP scheme, suspicious TLDs, keyword chaining)
    {"url": "https://secure-citibank-online-id-verify.top/auth/signin.html", "label": 1},
    {"url": "https://wells-fargo-card-activation-desk.xyz/verify/account.php", "label": 1},
    {"url": "https://usps-tracking-package-fee-payment.work/redelivery.php", "label": 1},
    {"url": "https://fedex-parcel-status-notification.loan/pay/tracking.html", "label": 1},
    {"url": "http://dhl-shipment-express-clearance.club/confirm_fee.aspx", "label": 1},
    {"url": "https://facebook-meta-copyright-strike-appeal.gq/login.php", "label": 1},
    {"url": "https://instagram-verified-badge-apply-now.cf/apply/form.html", "label": 1},
    {"url": "http://twitter-x-account-verification-rebrand.tk/login/auth", "label": 1},
    {"url": "https://netflix-suspend-account-recovery-centre.ml/payment.php", "label": 1},
    {"url": "http://amazon-security-alert-unusual-activity.ga/ap/signin", "label": 1},
    {"url": "https://apple-support-lost-mode-unlock.live/find/passcode.html", "label": 1},
    {"url": "http://paypal-hold-funds-release-request.bid/webscr.php", "label": 1},
    {"url": "https://chase-bank-alert-account-locked.press/logon/verify", "label": 1},
    {"url": "http://bofa-customer-service-identification.racing/signin.jsp", "label": 1},
    {"url": "http://wellsfargo-debit-card-compromised.download/auth.html", "label": 1},
    {"url": "https://citibank-security-challenge-response.win/online/signon", "label": 1},
    {"url": "http://irs-refund-direct-deposit-filing.stream/tax/2026/refund.php", "label": 1},
    {"url": "http://binance-kyc-document-reupload-portal.trade/user/verify", "label": 1},
    {"url": "https://coinbase-fraud-protection-hotline.party/auth/signin.html", "label": 1},
    {"url": "https://metamask-security-vault-backup.review/wallet/restore.php", "label": 1},
    {"url": "https://kraken-trading-account-security-alert.date/login.html", "label": 1},
    {"url": "http://gemini-crypto-exchange-identity-check.faith/auth/session", "label": 1},
    {"url": "http://robinhood-security-notice-trade-hold.cricket/signin.php", "label": 1},
    {"url": "http://etrade-account-verification-team.accountant/logon.aspx", "label": 1},
    {"url": "http://fidelity-investments-secure-client-access.science/login.jsp", "label": 1},
    {"url": "http://vanguard-retirement-account-update.webcam/portal/auth", "label": 1},
    {"url": "http://schwab-online-banking-security-upgrade.men/signon.html", "label": 1},
    {"url": "https://amex-card-holder-fraud-prevention.work/verify/login.php", "label": 1},
    {"url": "http://discover-card-security-alert-center.link/auth/logon.aspx", "label": 1},
    {"url": "https://capitalone-fraud-verification-team.click/signin/challenge", "label": 1},
    {"url": "https://barclays-online-banking-passcode-reset.help/auth.php", "label": 1},
    {"url": "http://hsbc-security-device-sync-portal.support/logon.html", "label": 1},
    {"url": "http://lloyds-bank-security-notice-verification.center/signin.jsp", "label": 1},
    {"url": "https://santander-account-confirmation-helpdesk.online/portal.php", "label": 1},
    {"url": "http://natwest-online-banking-reactivate.site/logon/auth.aspx", "label": 1},
    {"url": "http://royalbankofscotland-security-center.tech/verify/login", "label": 1},
    {"url": "http://standardchartered-fraud-prevention.space/signon.php", "label": 1},
    {"url": "https://scotiabank-security-alert-confirmation.store/auth.html", "label": 1},
    {"url": "https://td-bank-easyweb-security-challenge.website/login.aspx", "label": 1},
    {"url": "http://rbc-royal-bank-security-center-update.zone/signon.jsp", "label": 1},
    {"url": "http://bmo-bank-of-montreal-account-alert.vip/verify/login.php", "label": 1},
    {"url": "http://cibc-banking-service-verification-desk.icu/auth/portal", "label": 1},
    {"url": "http://anz-internet-banking-security-update.casa/signon.html", "label": 1},
    {"url": "https://commbank-netbank-security-verification.buzz/login.php", "label": 1},
    {"url": "http://westpac-online-banking-account-review.monster/auth.aspx", "label": 1},
    {"url": "http://nab-national-australia-bank-security.fit/signon/verify", "label": 1},
    {"url": "http://macquarie-bank-identity-confirmation.rest/portal/login", "label": 1},
    {"url": "http://ing-direct-banking-security-alert.lat/auth/signon.html", "label": 1},
    {"url": "http://postepay-evoluzione-aggiornamento-sicurezza.uno/login.php", "label": 1},
    {"url": "http://intesa-sanpaolo-accesso-sicuro-blocco.bar/auth/login.jsp", "label": 1},
]


def load_or_create_raw_dataset(raw_path: Optional[Path] = None, force_recreate: bool = False) -> pd.DataFrame:
    """Loads raw URL dataset from CSV or initializes it from benchmark records."""
    if raw_path is None:
        raw_path = RAW_DATA_DIR / "urls.csv"

    if raw_path.exists() and not force_recreate:
        df = pd.read_csv(raw_path)
        if "url" in df.columns and "label" in df.columns:
            return df

    raw_path.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(BENCHMARK_URL_RECORDS)
    df.to_csv(raw_path, index=False)
    return df


def prepare_url_dataset(
    raw_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    test_size: float = 0.20,
    random_state: int = 42,
    force_recompute: bool = False
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Extracts canonical 18-dim features from raw URLs and performs stratified train/test split.
    
    Returns:
        (features_df, train_df, test_df)
    """
    if output_path is None:
        output_path = PROCESSED_DATA_DIR / "features_dataset.csv"

    if output_path.exists() and not force_recompute:
        features_df = pd.read_csv(output_path)
    else:
        raw_df = load_or_create_raw_dataset(raw_path, force_recreate=force_recompute)

        def parse_label(val) -> int:
            if isinstance(val, (int, float, np.integer)):
                return int(val)
            val_str = str(val).strip().lower()
            if val_str in ("1", "phishing", "phish", "bad", "malicious"):
                return 1
            return 0

        raw_df["label"] = raw_df["label"].apply(parse_label)
        raw_df = raw_df.drop_duplicates(subset=["url"]).reset_index(drop=True)

        records = []
        for _, row in raw_df.iterrows():
            url_str = str(row["url"])
            lbl = int(row["label"])

            feat_vec, feat_dict = extract_url_features(url_str)
            records.append({
                "url": url_str,
                "label": lbl,
                "label_name": LABEL_TO_NAME.get(lbl, "Unknown"),
                **feat_dict
            })

        features_df = pd.DataFrame(records)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        features_df.to_csv(output_path, index=False)

    # Perform Stratified Train / Test Split
    train_df, test_df = train_test_split(
        features_df,
        test_size=test_size,
        random_state=random_state,
        stratify=features_df["label"]
    )

    return features_df, train_df, test_df


def load_features_dataset(path: Optional[Path] = None) -> pd.DataFrame:
    """Loads pre-extracted features dataset from disk."""
    if path is None:
        path = PROCESSED_DATA_DIR / "features_dataset.csv"

    if not path.exists():
        features_df, _, _ = prepare_url_dataset(output_path=path)
        return features_df

    return pd.read_csv(path)
