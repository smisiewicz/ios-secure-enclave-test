//
//  LocalViewController.m
//  SecureEnclaveKeyExchange
//
//  Created by Bastek on 11/5/19.
//

#import "LocalViewController.h"
#import "SEP.h"


@interface LocalViewController () {
    SecKeyRef privateKeyRef;
    SecKeyRef publicKeyRef;
}

@property (weak, nonatomic) IBOutlet UITextView *publicKeyText;
@property (weak, nonatomic) IBOutlet UITextField *msgInputText;
@property (weak, nonatomic) IBOutlet UITextView *msgEncryptedText;
@property (weak, nonatomic) IBOutlet UITextView *msgDecryptedText;

@end


@implementation LocalViewController

#pragma mark - Setup / Teardown
- (void)viewDidLoad {
    [super viewDidLoad];

    self.publicKeyText.text = [self generate];

    // small UI adjustments
    self.msgInputText.layer.borderWidth = 0.5;
    self.msgInputText.layer.cornerRadius = 7;
    self.msgInputText.layer.borderColor = UIColor.lightGrayColor.CGColor;
}


- (void)dealloc {
    [self cleanupRefs];
}


- (void)cleanupRefs {
    if (privateKeyRef) {
        CFRelease(privateKeyRef);
    }

    if (publicKeyRef) {
        CFRelease(publicKeyRef);
    }

    // reset UI
    self.msgEncryptedText.text = @"";
    self.msgDecryptedText.text = @"";
}


#pragma mark -
- (NSString * _Nullable)generate {
    [self cleanupRefs];

    CFErrorRef error = NULL;
    BOOL success = SEPGenerateKeyPair(&privateKeyRef, &publicKeyRef, &error);
    if (!success) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"Error when generating keypair: %@", err.localizedDescription);
        return nil;
    }
    return [SEP base64EncodedPublicKey:publicKeyRef];
}


#pragma mark - Action Handlers
- (IBAction)onGeneratePress {
    self.publicKeyText.text = [self generate];
}


- (IBAction)onEncryptPress {
    self.msgEncryptedText.text = [SEP encrypt:self.msgInputText.text
                                         with:publicKeyRef];
}


- (IBAction)onDecryptPress {
    self.msgDecryptedText.text = [SEP decrypt:self.msgEncryptedText.text
                                         with:privateKeyRef];
}

@end
