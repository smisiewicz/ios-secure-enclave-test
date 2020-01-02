//
//  ExchangeViewController.m
//  SecureEnclaveKeyExchange
//
//  Created by Bastek on 11/5/19.
//

#import "ExchangeViewController.h"
#import "SEP.h"

@import MultipeerConnectivity;


@interface ExchangeViewController () <MCSessionDelegate, MCBrowserViewControllerDelegate> {
    SecKeyRef myPrivateKeyRef; //my private key for message decryption
    SecKeyRef myPublicKeyRef; //my public key to share with other participant

    SecKeyRef userPublicKeyRef; //other participant's public key for outbound message encryption

    // just some simple multipeer setup to ease public key sharing (iOS testing only)
    MCSession *session;
    MCAdvertiserAssistant *advertizerAssistant;
}

@property (nonatomic, strong) MCPeerID *myPeerID;
@property (nonatomic, strong) MCPeerID *userPeerID;

@property (weak, nonatomic) IBOutlet UITextView *myPublicKeyText;
@property (weak, nonatomic) IBOutlet UITextView *userPublicKeyText;
@property (weak, nonatomic) IBOutlet UILabel *sessionStatusLabel;
@property (weak, nonatomic) IBOutlet UITextField *messageText;
@property (weak, nonatomic) IBOutlet UITextView *outputText;

@end


@implementation ExchangeViewController

#pragma mark - Setup / Teardown
- (void)viewDidLoad {
    [super viewDidLoad];

    self.myPublicKeyText.text = [self generate];

    _myPeerID = [[MCPeerID alloc] initWithDisplayName:UIDevice.currentDevice.name];
    session = [[MCSession alloc] initWithPeer:_myPeerID
                             securityIdentity:nil
                         encryptionPreference:MCEncryptionRequired];
    session.delegate = self;

    // small UI adjustments
    self.userPublicKeyText.layer.borderWidth = 0.5;
    self.userPublicKeyText.layer.cornerRadius = 7;
    self.userPublicKeyText.layer.borderColor = UIColor.lightGrayColor.CGColor;
}


- (void)dealloc {
    if (myPrivateKeyRef) { CFRelease(myPrivateKeyRef); }
    if (myPublicKeyRef) { CFRelease(myPublicKeyRef); }
    if (userPublicKeyRef) { CFRelease(userPublicKeyRef); }
}


#pragma mark -
- (NSString * _Nullable)generate {
    // cleanup existing
    if (myPrivateKeyRef) {
        CFRelease(myPrivateKeyRef);
        myPrivateKeyRef = nil;
    }
    if (myPublicKeyRef) {
        CFRelease(myPublicKeyRef);
        myPublicKeyRef = nil;
    }

    CFErrorRef error = NULL;
    BOOL success = SEPGenerateKeyPair(&myPrivateKeyRef, &myPublicKeyRef, &error);
    if (!success) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"Error when generating keypair: %@", err.localizedDescription);
        return nil;
    }
    return [SEP base64EncodedPublicKey:myPublicKeyRef];
}


- (void)startSession {
    advertizerAssistant = [[MCAdvertiserAssistant alloc] initWithServiceType:@"hws-kb"
                                                               discoveryInfo:nil
                                                                     session:session];
    [advertizerAssistant start];

    // no callbacks for this, wtf apple?
    self.sessionStatusLabel.text = @"Started.";
}


- (void)joinSession {
    MCBrowserViewController *vc = [[MCBrowserViewController alloc] initWithServiceType:@"hws-kb"
                                                                               session:session];
    vc.delegate = self;
    [self presentViewController:vc
                       animated:YES
                     completion:nil];
}


- (void)sharePublicKey {
    if (!_userPeerID) {
        NSLog(@"User peerID does not exist, ignoring.");
        return;
    }

    NSDictionary *dict = @{@"type": @"key",
                           @"val": self.myPublicKeyText.text};
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
    if (data) {
        NSLog(@"Sharing my public key with user: %@", _userPeerID.displayName);
        NSError *error = nil;
        [session sendData:data
                  toPeers:@[_userPeerID]
                 withMode:MCSessionSendDataReliable
                    error:&error];

        if (error) {
            NSLog(@"Failed to share public key data with: %@, error: %@", _userPeerID.displayName, error.localizedDescription);
        }
    }
}


- (void)sendMessage {
    if (!userPublicKeyRef) {
        NSLog(@"User public key does not exist, ignoring.");
        return;
    }

    NSString *encrypted = [SEP encrypt:self.messageText.text with:userPublicKeyRef];

    NSDictionary *dict = @{@"type": @"msg",
                           @"val": encrypted};
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
    if (data) {
        NSLog(@"Sharing my public key with user: %@", _userPeerID.displayName);
        NSError *error = nil;
        [session sendData:data
                  toPeers:@[_userPeerID]
                 withMode:MCSessionSendDataReliable
                    error:&error];

        if (error) {
            NSLog(@"Failed to share public key data with: %@, error: %@", _userPeerID.displayName, error.localizedDescription);
        }
    } else {
        NSLog(@"Failed to send message to peer ID: %@. Failed to create JSON data.", _userPeerID.displayName);
    }
}


- (void)updateUserKey:(NSString *)val {
    BOOL success = SEPCreatePublicKeyRefFromBase64String(val, &userPublicKeyRef);
    if (success) {
        self.userPublicKeyText.text = val;
    }
}


- (void)logEncrypted:(NSString *)val {
    NSString *message = [NSString stringWithFormat:@"ENCRYPTED: %@", val];
    [self log:message];

    NSString *decrypted = [NSString stringWithFormat:@"DECRYPTED: %@", [SEP decrypt:val with:myPrivateKeyRef]];
    [self log:decrypted];
}


- (void)log:(NSString *)message {
    self.outputText.text = [self.outputText.text stringByAppendingFormat:@"%@\n\n", message];

    if(self.outputText.text.length > 0 ) {
        NSRange bottom = NSMakeRange(self.outputText.text.length - 1, 1);
        [self.outputText scrollRangeToVisible:bottom];
    }
}


#pragma mark - Action Handlers
- (IBAction)onGeneratePress {
    self.myPublicKeyText.text = [self generate];

    // update public key if multipeer connection is open
    if (self.userPeerID) {
        [self sharePublicKey];
    }
}


- (IBAction)onStartSessionPress {
    [self startSession];
}


- (IBAction)onJoinSessionPress {
    [self joinSession];
}


- (IBAction)onSendMsgPress {
    [self.messageText resignFirstResponder];
    [self sendMessage];
}


#pragma mark - Multipeer Session Delegate
- (void)session:(MCSession *)session peer:(MCPeerID *)peerID didChangeState:(MCSessionState)state
{
    dispatch_async(dispatch_get_main_queue(), ^{
        switch (state) {
            case MCSessionStateNotConnected:
                NSLog(@"Multipeer sesion state change: not connected: %@", peerID.displayName);
                self.sessionStatusLabel.text = [NSString stringWithFormat:@"Disconnected (%@)", peerID.displayName];
                break;

            case MCSessionStateConnecting:
                NSLog(@"Multipeer sesion state change: connecting: %@", peerID.displayName);
                self.sessionStatusLabel.text = [NSString stringWithFormat:@"Connecting (%@)", peerID.displayName];
                break;

            case MCSessionStateConnected:
                NSLog(@"Multipeer sesion state change: connected: %@", peerID.displayName);
                self.sessionStatusLabel.text = [NSString stringWithFormat:@"Connected (%@)", peerID.displayName];

                // update user peer ID and automatically share public keys
                self.userPeerID = peerID;
                [self sharePublicKey];
                break;
        }
    });
}


// Received data from remote peer.
- (void)session:(MCSession *)session didReceiveData:(NSData *)data fromPeer:(MCPeerID *)peerID
{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSLog(@">>> Multipeer session - did receive data from peer with ID: %@", peerID.displayName);

        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSString *type = dict[@"type"];
        NSString *val = dict[@"val"];

        if ([type isEqualToString:@"key"]) {
            [self updateUserKey:val];
        }
        else if ([type isEqualToString:@"msg"]) {
            [self logEncrypted:val];
        }
    });
}


// Received a byte stream from remote peer.
- (void)    session:(MCSession *)session
   didReceiveStream:(NSInputStream *)stream
           withName:(NSString *)streamName
           fromPeer:(MCPeerID *)peerID
{
    NSLog(@">>> Multipeer session - did receive stream with name: %@", streamName);
}


// Start receiving a resource from remote peer.
- (void)                    session:(MCSession *)session
  didStartReceivingResourceWithName:(NSString *)resourceName
                           fromPeer:(MCPeerID *)peerID
                       withProgress:(NSProgress *)progress
{
    NSLog(@">>> Multipeer session - did start receiving resource with name: %@", resourceName);
}


// Finished receiving a resource from remote peer and saved the content
// in a temporary location - the app is responsible for moving the file
// to a permanent location within its sandbox.
- (void)                    session:(MCSession *)session
 didFinishReceivingResourceWithName:(NSString *)resourceName
                           fromPeer:(MCPeerID *)peerID
                              atURL:(nullable NSURL *)localURL
                          withError:(nullable NSError *)error
{
    NSLog(@">>> Multipeer session - did finish receiving resource with name: %@", resourceName);
}


#pragma mark - Multipeer Browser Delegate
- (void)browserViewControllerDidFinish:(MCBrowserViewController *)browserViewController
{
    NSLog(@">>> Browser view controller did finish.");
    [browserViewController dismissViewControllerAnimated:YES completion:nil];
}


// Notifies delegate that the user taps the cancel button.
- (void)browserViewControllerWasCancelled:(MCBrowserViewController *)browserViewController
{
    NSLog(@">>> Browser view controller was cancelled.");
    [browserViewController dismissViewControllerAnimated:YES completion:nil];
}

@end
