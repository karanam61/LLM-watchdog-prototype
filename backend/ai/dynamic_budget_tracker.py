"""
Dynamic Budget Tracker - AI API Cost Control
=============================================

This module manages the daily budget for AI API calls, preventing
runaway spending while ensuring critical alerts get analyzed.

WHAT THIS FILE DOES:
1. Tracks cumulative AI API costs throughout the day
2. Allocates budget between priority and standard queues
3. Reserves 20% budget for late-arriving critical alerts
4. Resets budget daily at midnight
5. Blocks processing when budget exhausted

WHY THIS EXISTS:
- Claude API costs money ($3-15 per million tokens)
- Uncontrolled spending can quickly exceed budgets
- Critical alerts must always be analyzed (priority reserve)
- Standard alerts can wait if budget is low

BUDGET STRATEGY:
1. Daily limit (default $2.00)
2. Priority queue gets budget first
3. Reserve 20% for late-arriving critical alerts
4. Standard queue uses remaining budget

USAGE:
    tracker = DynamicBudgetTracker(daily_limit=2.00)
    can_proceed, reason = tracker.check_budget(estimated_cost)
    tracker.record_cost(actual_cost, queue_type='priority')

Author: AI-SOC Watchdog System
"""

from datetime import datetime


class DynamicBudgetTracker:
    """
    Dynamic budget allocation with queue-level processing
    
    Strategy:
    1. Priority queue gets budget first (process all if possible)
    2. Standard queue uses remaining budget (process what we can afford)
    3. Reserve 20% for late-arriving priority alerts
    """
    
    def __init__(self, daily_limit=2.00, priority_reserve=0.20):
        """
        Initialize dynamic budget tracker
        
        Args:
            daily_limit: Total daily budget in dollars (default $2.00)
            priority_reserve: Percentage to reserve for priority (default 20%)
        """
        self.daily_limit = daily_limit
        self.priority_reserve = priority_reserve
        self.reset_date = datetime.now().date()
        
        # Overall tracking
        self.spent_today = 0.0
        self.calls_today = 0
        
        # Queue-level metrics
        self.queue_metrics = {
            'priority': {
                'batches_processed': 0,
                'alerts_analyzed': 0,
                'alerts_skipped': 0,
                'total_cost': 0.0
            },
            'standard': {
                'batches_processed': 0,
                'alerts_analyzed': 0,
                'alerts_skipped': 0,
                'total_cost': 0.0
            }
        }
        
        print(f"[*] Dynamic Budget Tracker initialized")
        print(f"   Daily limit: ${daily_limit:.2f}")
        print(f"   Priority reserve: {priority_reserve * 100:.0f}%")
        print(f"   Strategy: Priority first, standard uses remainder")
    
    def _check_daily_reset(self):
        """Reset counters at midnight"""
        today = datetime.now().date()
        
        if today > self.reset_date:
            print(f"\n[*] New day - resetting budget")
            self._print_daily_summary()
            
            # Reset
            self.spent_today = 0.0
            self.calls_today = 0
            self.queue_metrics = {
                'priority': {'batches_processed': 0, 'alerts_analyzed': 0, 'alerts_skipped': 0, 'total_cost': 0.0},
                'standard': {'batches_processed': 0, 'alerts_analyzed': 0, 'alerts_skipped': 0, 'total_cost': 0.0}
            }
            self.reset_date = today
    
    def can_process_queue(self, queue_type, queue_size, cost_per_alert=0.01):
        """
        Check if we can process an entire queue (batch)
        
        Args:
            queue_type: 'priority' or 'standard'
            queue_size: Number of alerts in queue
            cost_per_alert: Estimated cost per alert (default $0.01)
        
        Returns:
            Tuple of (can_process_count: int, estimated_cost: float, reason: str)
        """
        self._check_daily_reset()
        
        remaining = self.daily_limit - self.spent_today
        total_needed = queue_size * cost_per_alert
        
        print(f"\n[*] Queue Budget Check:")
        print(f"   Queue: {queue_type.upper()}")
        print(f"   Alerts in queue: {queue_size}")
        print(f"   Cost per alert: ${cost_per_alert:.6f}")
        print(f"   Total needed: ${total_needed:.4f}")
        print(f"   Budget remaining: ${remaining:.4f}")
        
        if queue_type == 'priority':
            # Priority queue: Process as many as budget allows
            if remaining >= total_needed:
                print(f"   [OK] Can process entire priority queue")
                return (queue_size, total_needed, "Full priority queue processable")
            else:
                # Partial processing
                can_process = int(remaining / cost_per_alert)
                partial_cost = can_process * cost_per_alert
                print(f"   [WARNING]  Can only process {can_process}/{queue_size} priority alerts")
                return (can_process, partial_cost, f"Budget allows {can_process} alerts")
        
        else:  # standard queue
            # Reserve budget for potential priority alerts
            reserved = self.daily_limit * self.priority_reserve
            available_for_standard = remaining - reserved
            
            print(f"   Reserved for priority: ${reserved:.4f}")
            print(f"   Available for standard: ${available_for_standard:.4f}")
            
            if available_for_standard >= total_needed:
                print(f"   [OK] Can process entire standard queue")
                return (queue_size, total_needed, "Full standard queue processable")
            elif available_for_standard > 0:
                # Partial processing
                can_process = int(available_for_standard / cost_per_alert)
                partial_cost = can_process * cost_per_alert
                print(f"   [WARNING]  Can only process {can_process}/{queue_size} standard alerts")
                return (can_process, partial_cost, f"Budget allows {can_process} alerts")
            else:
                print(f"   [ERROR] No budget available for standard queue")
                return (0, 0, "Budget reserved for priority")
    
    def record_queue_processing(self, queue_type, alerts_analyzed, alerts_skipped, actual_cost):
        """
        Record metrics after processing a queue batch
        
        Args:
            queue_type: 'priority' or 'standard'
            alerts_analyzed: Number of alerts actually analyzed
            alerts_skipped: Number of alerts skipped (budget exhausted)
            actual_cost: Actual total cost for this batch
        """
        
        # Update overall tracking
        self.spent_today += actual_cost
        self.calls_today += alerts_analyzed
        
        # Update queue metrics
        metrics = self.queue_metrics[queue_type]
        metrics['batches_processed'] += 1
        metrics['alerts_analyzed'] += alerts_analyzed
        metrics['alerts_skipped'] += alerts_skipped
        metrics['total_cost'] += actual_cost
        
        # Calculate stats
        remaining = self.daily_limit - self.spent_today
        percent_used = (self.spent_today / self.daily_limit) * 100
        avg_cost = actual_cost / alerts_analyzed if alerts_analyzed > 0 else 0
        
        print(f"\n[*] Queue Processing Recorded:")
        print(f"   Queue: {queue_type.upper()}")
        print(f"   Batch cost: ${actual_cost:.4f}")
        print(f"   Alerts analyzed: {alerts_analyzed}")
        print(f"   Alerts skipped: {alerts_skipped}")
        print(f"   Avg cost/alert: ${avg_cost:.6f}")
        print(f"   Daily total: ${self.spent_today:.4f} / ${self.daily_limit:.2f} ({percent_used:.1f}%)")
        print(f"   Remaining: ${remaining:.4f}")
        
        # Warnings
        if percent_used >= 80:
            print(f"   [WARNING]  Daily budget at {percent_used:.1f}%")
    
    def get_stats(self):
        """
        Get comprehensive budget and queue statistics
        
        Returns:
            Dictionary with detailed metrics
        """
        self._check_daily_reset()
        
        total_analyzed = sum(q['alerts_analyzed'] for q in self.queue_metrics.values())
        total_skipped = sum(q['alerts_skipped'] for q in self.queue_metrics.values())
        total_alerts = total_analyzed + total_skipped
        
        return {
            'date': self.reset_date.isoformat(),
            'budget': {
                'daily_limit': self.daily_limit,
                'spent': self.spent_today,
                'remaining': self.daily_limit - self.spent_today,
                'percent_used': (self.spent_today / self.daily_limit) * 100
            },
            'overall': {
                'total_alerts': total_alerts,
                'alerts_analyzed': total_analyzed,
                'alerts_skipped': total_skipped,
                'analysis_rate': (total_analyzed / total_alerts * 100) if total_alerts > 0 else 0,
                'total_calls': self.calls_today,
                'average_cost_per_call': self.spent_today / self.calls_today if self.calls_today > 0 else 0
            },
            'priority_queue': {
                'batches_processed': self.queue_metrics['priority']['batches_processed'],
                'alerts_analyzed': self.queue_metrics['priority']['alerts_analyzed'],
                'alerts_skipped': self.queue_metrics['priority']['alerts_skipped'],
                'total_cost': self.queue_metrics['priority']['total_cost'],
                'avg_cost_per_alert': (
                    self.queue_metrics['priority']['total_cost'] / 
                    self.queue_metrics['priority']['alerts_analyzed']
                ) if self.queue_metrics['priority']['alerts_analyzed'] > 0 else 0
            },
            'standard_queue': {
                'batches_processed': self.queue_metrics['standard']['batches_processed'],
                'alerts_analyzed': self.queue_metrics['standard']['alerts_analyzed'],
                'alerts_skipped': self.queue_metrics['standard']['alerts_skipped'],
                'total_cost': self.queue_metrics['standard']['total_cost'],
                'avg_cost_per_alert': (
                    self.queue_metrics['standard']['total_cost'] / 
                    self.queue_metrics['standard']['alerts_analyzed']
                ) if self.queue_metrics['standard']['alerts_analyzed'] > 0 else 0
            }
        }
    
    def _print_daily_summary(self):
        """Print end-of-day summary"""
        stats = self.get_stats()
        
        print("\n" + "="*70)
        print("DAILY BUDGET SUMMARY")
        print("="*70)
        
        print(f"\nBudget:")
        print(f"  Limit: ${stats['budget']['daily_limit']:.2f}")
        print(f"  Spent: ${stats['budget']['spent']:.4f} ({stats['budget']['percent_used']:.1f}%)")
        print(f"  Remaining: ${stats['budget']['remaining']:.4f}")
        
        print(f"\nOverall:")
        print(f"  Total alerts: {stats['overall']['total_alerts']}")
        print(f"  Analyzed: {stats['overall']['alerts_analyzed']}")
        print(f"  Skipped: {stats['overall']['alerts_skipped']}")
        print(f"  Analysis rate: {stats['overall']['analysis_rate']:.1f}%")
        
        print(f"\nPriority Queue:")
        print(f"  Batches: {stats['priority_queue']['batches_processed']}")
        print(f"  Analyzed: {stats['priority_queue']['alerts_analyzed']}")
        print(f"  Skipped: {stats['priority_queue']['alerts_skipped']}")
        print(f"  Cost: ${stats['priority_queue']['total_cost']:.4f}")
        
        print(f"\nStandard Queue:")
        print(f"  Batches: {stats['standard_queue']['batches_processed']}")
        print(f"  Analyzed: {stats['standard_queue']['alerts_analyzed']}")
        print(f"  Skipped: {stats['standard_queue']['alerts_skipped']}")
        print(f"  Cost: ${stats['standard_queue']['total_cost']:.4f}")


if __name__ == '__main__':
    """
    Test dynamic budget tracker with queue-level processing
    """
    print("="*70)
    print("DYNAMIC BUDGET TRACKER TEST")
    print("="*70)
    
    tracker = DynamicBudgetTracker(daily_limit=2.00, priority_reserve=0.20)
    
    # Scenario 1: Light priority day (your example)
    print("\n" + "="*70)
    print("SCENARIO 1: Light Priority Day (1 critical, 499 low-severity)")
    print("="*70)
    
    # Process priority queue (only 1 alert)
    print("\n[Step 1] Process Priority Queue:")
    can_process, cost, reason = tracker.can_process_queue('priority', queue_size=1, cost_per_alert=0.01)
    print(f"Decision: Process {can_process} alerts for ${cost:.4f}")
    
    if can_process > 0:
        tracker.record_queue_processing('priority', alerts_analyzed=1, alerts_skipped=0, actual_cost=0.01)
    
    # Process standard queue (499 alerts)
    print("\n[Step 2] Process Standard Queue:")
    can_process, cost, reason = tracker.can_process_queue('standard', queue_size=499, cost_per_alert=0.01)
    print(f"Decision: Process {can_process} alerts for ${cost:.4f}")
    
    if can_process > 0:
        # Simulate analyzing the affordable alerts
        actual_analyzed = can_process
        actual_skipped = 499 - can_process
        tracker.record_queue_processing('standard', alerts_analyzed=actual_analyzed, alerts_skipped=actual_skipped, actual_cost=cost)
    
    # Scenario 2: Heavy priority day
    print("\n" + "="*70)
    print("SCENARIO 2: Heavy Priority Day (400 critical, 100 low-severity)")
    print("="*70)
    
    # Reset for new scenario
    tracker.spent_today = 0.0
    tracker.calls_today = 0
    
    # Process priority queue (400 alerts)
    print("\n[Step 1] Process Priority Queue:")
    can_process, cost, reason = tracker.can_process_queue('priority', queue_size=400, cost_per_alert=0.01)
    print(f"Decision: Process {can_process} alerts for ${cost:.4f}")
    
    if can_process > 0:
        actual_skipped = 400 - can_process
        tracker.record_queue_processing('priority', alerts_analyzed=can_process, alerts_skipped=actual_skipped, actual_cost=cost)
    
    # Process standard queue (100 alerts)
    print("\n[Step 2] Process Standard Queue:")
    can_process, cost, reason = tracker.can_process_queue('standard', queue_size=100, cost_per_alert=0.01)
    print(f"Decision: Process {can_process} alerts for ${cost:.4f}")
    
    if can_process > 0:
        actual_skipped = 100 - can_process
        tracker.record_queue_processing('standard', alerts_analyzed=can_process, alerts_skipped=actual_skipped, actual_cost=cost)
    
    # Final statistics
    print("\n" + "="*70)
    print("FINAL STATISTICS (Scenario 2):")
    print("="*70)
    
    stats = tracker.get_stats()
    print(f"\nBudget: ${stats['budget']['spent']:.4f} / ${stats['budget']['daily_limit']:.2f}")
    print(f"Efficiency: {stats['overall']['analysis_rate']:.1f}% of alerts analyzed")
    print(f"Priority: {stats['priority_queue']['alerts_analyzed']} analyzed, {stats['priority_queue']['alerts_skipped']} skipped")
    print(f"Standard: {stats['standard_queue']['alerts_analyzed']} analyzed, {stats['standard_queue']['alerts_skipped']} skipped")
    
    print("\n" + "="*70)
    print("[OK] DYNAMIC BUDGET TRACKER TEST COMPLETE")
    print("="*70)
    
    print("\nKey Observations:")
    print("1. Light priority day: 1 critical + 159 low-severity analyzed (160 total)")
    print("2. Heavy priority day: 200 critical analyzed, standard queue skipped")
    print("3. Budget dynamically allocated based on actual workload [OK]")
