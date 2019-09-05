from detection import DetectionModule
import pickle

class EvaluationUtils:
    """
    This class manages the evaluation output of the performance of DECANTeR.
    """
    def __init__(self, alerts, benign, fingerprint_to_timestamps_training, fingerprint_to_timestamps_testing):
        self.alerts = alerts
        self.benign = benign
        self.unique_fing = self._unique_fingerprints()
        self.fingerprint_to_timestamps_training = fingerprint_to_timestamps_training
        self.fingerprint_to_timestamps_testing = fingerprint_to_timestamps_testing

    def detection_performance_2(self):
        """
        This method evaluates the true positives (tp), false positives (fp), true negatives (tn), and false negatives (fn).

        There are two modes of evaluation: a) without retraining and b) with retraining.

        a) Without retraining: the system never updates. Whenever a fingerprint is triggered as fp, the system is NOT updated.
           Everytime the same fingerprint appears in the traffic will always triggered. E.g., when a new software is installed and starts
           communicating raising an alert, the alert will be repeated also for the next communication.

        b) With retraining: the system always updates. Whenever a fingerprint is triggered as fp, we assume an operator "trains" they system
           adding the new fingerprint to the set of known fingerprints. E.g., when a new software is installed and starts communicating
           raising an alert, the alert will NOT be appear in the future communications, because is known to be "trusted".

        This method outputs the classificatoin results for number of fingerprints and requests. DECANTeR works based on fingerprints, which is
        the real representation of its performance. However, in order to compare it with DUMONT, we have added an analysis also per requests, which 
        works as follows:
        - The number of fp/tp/fn/tn is the amount of requests contained in the fingerprint classified as fp/tp/fn/tn.

        E.g., If a fingerprint is classified as tn and it represents a cluster containing 10 requests. We add 10 to the number of tn.

        There are four outputs classification results (tp, fp, tn, fn):
        1) Output of fingerprints WITHOUT retraining
        2) Output of fingerprints WITH retraining
        3) Output of HTTP requests WITHOUT retraining
        4) Output of HTTP requests WITH retraining

        """
        tp = []
        tn = []
        fp = []
        fn = []

        timestamps_with_alerts_training = []
        timestamps_with_alerts_testing = []

        for a in self.alerts:
            if int(a.is_malicious) == 1:
                tp.append(a)

                timestamps_with_alerts_training.extend( self.fingerprint_to_timestamps_training[a] )
                timestamps_with_alerts_testing.extend( self.fingerprint_to_timestamps_testing[a] )

            else:
                fp.append(a)
        
        for b in self.benign:
            if int(b.is_malicious) == 1:
                fn.append(b)
            else:
                tn.append(b)
                
        tp_fings = len(tp)
        tn_fings = len(tn)
        fp_fings = len(fp)
        fn_fings = len(fn)
        
        print """
            ********************************************
                 Detection Performance - fingerprints
            ********************************************
                Malicious                           Benign
            -----------------------             -----------------------
            True positives:  {:<10}         True negatives:  {:<10}
            False negatives: {:<10}         False positives: {:<10}
        """.format(tp_fings, tn_fings, fn_fings, fp_fings)
        
        retrained_fp = []
        
        for a in self.unique_fing:
            if a in self.alerts and int(a.is_malicious) == 0:
                retrained_fp.append(a)
                
        retrained_fp_fings = len(retrained_fp)
        
        retrained_tp_fings = tp_fings
        retrained_tn_fings = tn_fings + (fp_fings - retrained_fp_fings)
        retrained_fn_fings = fn_fings
        
        
        print """
            ***************************************************************
                 Detection Performance - fingerprints - after retraining
            ***************************************************************
                Malicious                           Benign
            -----------------------             -----------------------
            True positives:  {:<10}         True negatives:  {:<10}
            False negatives: {:<10}         False positives: {:<10}
        """.format(retrained_tp_fings, retrained_tn_fings, retrained_fn_fings, retrained_fp_fings)
                
                
        tp_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in tp])
        tn_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in tn])
        fp_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in fp])
        fn_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in fn])
            
        print """
            ****************************************
                 Detection Performance - requests
            ****************************************
                Malicious                           Benign
            -----------------------             -----------------------
            True positives:  {:<10}         True negatives:  {:<10}
            False negatives: {:<10}         False positives: {:<10}
        """.format(tp_reqs, tn_reqs, fn_reqs, fp_reqs)
        
        retrained_fp = []
        
        for a in self.unique_fing:
            if a in self.alerts and int(a.is_malicious) == 0:
                retrained_fp.append(a)
                
        retrained_fp_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in retrained_fp])
        
        retrained_tp_reqs = tp_reqs
        retrained_tn_reqs = tn_reqs + (fp_reqs - retrained_fp_reqs)
        retrained_fn_reqs = fn_reqs
                
        
        print """
            **********************************************************
                Detection Performance - requests - after retraining
            **********************************************************
                Malicious                          Benign
            -----------------------             -----------------------
            True positives:  {:<10}         True negatives:  {:<10}
            False negatives: {:<10}         False positives: {:<10}
        """.format(retrained_tp_reqs, retrained_tn_reqs, retrained_fn_reqs, retrained_fp_reqs)


        ## TODO (JOE): print out requests that trigger alerts.... (timestamps + hosts)
        # (alternatively can log...)
        print "----------"
        print "output added by Joe:"
        print "timestamps_with_alerts_training:\n"
        print timestamps_with_alerts_training
        print "timestamps_with_alerts_testing:\n"
        print timestamps_with_alerts_testing
        with open('./timestamps_with_alerts_training.txt', 'w') as f:
            pickle.dump(timestamps_with_alerts_training,f)
        with open('./timestamps_with_alerts_testing.txt', 'w') as f:
            pickle.dump(timestamps_with_alerts_testing, f)

        print "---------\n"

        return tp_reqs, tn_reqs, fn_reqs, fp_reqs
        
        
    def output_requests(self):
        req_alerts      = 0
        req_benign      = 0
        req_uniq_alerts = 0
        
        for f in self.alerts:
            for domain, number_req in f.hosts:
                req_alerts += number_req
        
        for f in self.benign:
            for domain, number_req in f.hosts:
                req_benign += number_req
                
        for f in self.unique_fing:
            for domain, number_req in f.hosts:
                req_uniq_alerts += number_req
                
        print """
            *************************************
                      Fingerprints Stats
            *************************************
            Benign Fingerprints: {}
            Alerts Fingerprints: {}
            ----> Unique Alerts: {}
            
            *************************************
                        Requests Stats
            *************************************
            Benign Requests:              {}
            Alerts Requests:              {}
            ----> Unique Alerts Requests: {}
        """.format(len(self.benign), len(self.alerts), len(self.unique_fing), req_benign, req_alerts, req_uniq_alerts)
        
        
    def _unique_fingerprints(self):
        '''
            This method identifies the set of unique alerts. We assume an operator would add the fingerprints
            of false positives to the set of trained fingerprints, to avoid false positives in the future.
            
            We identify two fingerprints as similar, the same we do it in the detection module.
            
            Param
            ---------
            return:
                Set of unique Fingerprints. 
        '''
        detector = DetectionModule()
        unique_alerts = []
        
        if self.alerts:
            unique_alerts.append(self.alerts[0])
            
        for i in range(1, len(self.alerts)):
            res = False
            for uniq_a in unique_alerts:
                if detector.similarity_check(self.alerts[i], uniq_a):
                    res = True
            if res == False:
                unique_alerts.append(self.alerts[i])
            
        return unique_alerts
            

